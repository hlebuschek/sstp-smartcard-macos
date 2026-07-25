"""macOS data plane: the utun interface plus address, route and DNS setup.

A packet tunnel would normally be a NetworkExtension provider, which requires
an Apple-issued entitlement. A utun socket gives the same kernel interface from
an ordinary process, at the cost of needing root.
"""

from __future__ import annotations

import fcntl
import json
import os
import socket
import struct
import subprocess

from . import log

logger = log.get("net")

# Routes and DNS outlive the process that set them, so what was changed is
# recorded on disk: a crashed client would otherwise leave the machine with a
# default route pointing at a dead interface and no way to reach anything.
STATE_FILE = "/var/run/sstp-client.json"

# Where macOS looks for per-domain resolver configuration.
RESOLVER_DIR = "/etc/resolver"

AF_SYSTEM = 32
SYSPROTO_CONTROL = 2
AF_SYS_CONTROL = 2
UTUN_CONTROL_NAME = b"com.apple.net.utun_control"
UTUN_OPT_IFNAME = 2
CTLIOCGINFO = 0xC0644E03

# Every utun frame is prefixed with the address family in network byte order.
AF_INET_HEADER = struct.pack("!I", socket.AF_INET)


class NetworkError(Exception):
    pass


class Utun:
    def __init__(self):
        self.socket: socket.socket | None = None
        self.name = ""
        self.rx_bytes = 0
        self.tx_bytes = 0

    def open(self) -> str:
        try:
            control = socket.socket(AF_SYSTEM, socket.SOCK_DGRAM, SYSPROTO_CONTROL)
        except OSError as exc:
            raise NetworkError(f"cannot create utun control socket: {exc}") from exc

        info = struct.pack("<I96s", 0, UTUN_CONTROL_NAME)
        try:
            info = fcntl.ioctl(control, CTLIOCGINFO, info)
        except OSError as exc:
            raise NetworkError(f"CTLIOCGINFO failed: {exc}") from exc
        control_id = struct.unpack("<I96s", info)[0]

        # Unit 0 asks the kernel for the first free utun device.
        try:
            control.connect((control_id, 0))
        except OSError as exc:
            raise NetworkError(
                f"cannot attach to utun (are you running as root?): {exc}"
            ) from exc

        self.name = control.getsockopt(
            SYSPROTO_CONTROL, UTUN_OPT_IFNAME, 256
        ).rstrip(b"\x00").decode()
        self.socket = control
        logger.info("opened %s", self.name)
        return self.name

    def fileno(self) -> int:
        return self.socket.fileno()

    def read(self) -> bytes:
        """Read one IP packet, stripping the address family prefix."""
        data = self.socket.recv(4096)
        if len(data) <= 4:
            return b""
        self.tx_bytes += len(data) - 4
        return data[4:]

    def write(self, packet: bytes) -> None:
        self.rx_bytes += len(packet)
        self.socket.send(AF_INET_HEADER + packet)

    def close(self) -> None:
        if self.socket is not None:
            self.socket.close()
            self.socket = None


def _run(command: list[str]) -> None:
    logger.debug("run %s", " ".join(command))
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        raise NetworkError(
            f"{' '.join(command)} failed: {result.stderr.strip() or result.stdout.strip()}"
        )


def _output(command: list[str]) -> str:
    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout if result.returncode == 0 else ""


def configure_interface(name: str, local: str, peer: str, mtu: int) -> None:
    _run(["ifconfig", name, "inet", local, peer, "netmask", "255.255.255.255", "up"])
    _run(["ifconfig", name, "mtu", str(mtu)])
    logger.info("configured %s: %s -> %s (mtu %d)", name, local, peer, mtu)


def default_gateway() -> str | None:
    for line in _output(["route", "-n", "get", "default"]).splitlines():
        line = line.strip()
        if line.startswith("gateway:"):
            return line.split()[1]
    return None


class Routes:
    """Adds routes and remembers them so they can be withdrawn on exit."""

    def __init__(self):
        self._added: list[list[str]] = []

    def add(self, destination: str, gateway: str, interface: str | None = None) -> None:
        command = ["route", "-n", "add", "-net", destination]
        command += ["-interface", interface] if interface else [gateway]
        try:
            _run(command)
        except NetworkError as exc:
            logger.warning("could not add route %s: %s", destination, exc)
            return
        logger.info("route %s via %s", destination, interface or gateway)
        self._added.append([destination, gateway, interface or ""])

    @property
    def state(self) -> list[list[str]]:
        return [list(entry) for entry in self._added]

    @classmethod
    def from_state(cls, entries) -> "Routes":
        routes = cls()
        routes._added = [list(entry) for entry in entries]
        return routes

    def add_host(self, destination: str, gateway: str = "",
                 interface: str | None = None) -> None:
        command = ["route", "-n", "add", "-host", destination]
        command += ["-interface", interface] if interface else [gateway]
        try:
            _run(command)
        except NetworkError as exc:
            logger.warning("could not add host route %s: %s", destination, exc)
            return
        logger.info("route %s via %s", destination, interface or gateway)
        self._added.append([destination, gateway, interface or ""])

    def withdraw(self) -> None:
        for destination, gateway, interface in reversed(self._added):
            command = ["route", "-n", "delete", destination]
            if interface:
                command += ["-interface", interface]
            subprocess.run(command, capture_output=True)
        self._added.clear()


def redirect_default(interface: str, peer: str, server_address: str) -> Routes:
    """Send all traffic through the tunnel while keeping the server reachable."""
    routes = Routes()
    gateway = default_gateway()
    if gateway is None:
        raise NetworkError("no default gateway found")
    routes.add_host(server_address, gateway)
    # Two /1 routes outrank the existing default route without deleting it.
    routes.add("0.0.0.0/1", peer, interface)
    routes.add("128.0.0.0/1", peer, interface)
    logger.info("default route redirected through %s", interface)
    return routes


class Resolver:
    """Points macOS DNS at the tunnel's servers, restoring the previous state.

    Two modes. By default every active network service is pointed at the
    tunnel's servers, which is what the Windows client does and what makes
    corporate names resolve whatever suffix they carry. Naming domains
    explicitly switches to per-domain resolver files, which leaves the rest of
    the internet resolving as before at the cost of having to know every
    corporate suffix in advance.
    """

    def __init__(self):
        self._services: list[tuple[str, list[str]]] = []
        self._files: list[str] = []

    def apply(self, servers: list[str], domains: list[str] | None = None) -> None:
        if not servers:
            return
        if domains:
            self._apply_scoped(servers, domains)
        else:
            self._apply_globally(servers)
        self._flush()

    def _apply_globally(self, servers: list[str]) -> None:
        for service in self._network_services():
            previous = self._current(service)
            # Our own servers already there means a previous run died without
            # restoring. Saving them as "previous" would make the damage
            # permanent, one run cementing the last one's leftovers.
            if previous == servers:
                previous = []
            try:
                _run(["networksetup", "-setdnsservers", service] + servers)
            except NetworkError as exc:
                logger.debug("cannot set DNS for %r: %s", service, exc)
                continue
            self._services.append((service, previous))
        if self._services:
            logger.info("DNS servers set to %s", ", ".join(servers))

    def _apply_scoped(self, servers: list[str], domains: list[str]) -> None:
        os.makedirs(RESOLVER_DIR, exist_ok=True)
        body = "".join(f"nameserver {server}\n" for server in servers)
        # A UPN carries the domain in whatever case the CA felt like using, and
        # resolver files are matched by file name.
        for domain in {d.strip(". ").lower() for d in domains if d.strip(". ")}:
            path = os.path.join(RESOLVER_DIR, domain)
            if os.path.exists(path):
                logger.warning("%s belongs to something else, leaving it alone", path)
                continue
            try:
                with open(path, "w") as handle:
                    handle.write(body)
            except OSError as exc:
                logger.warning("cannot write %s: %s", path, exc)
                continue
            self._files.append(path)
        if self._files:
            logger.info(
                "DNS for %s -> %s",
                ", ".join(os.path.basename(path) for path in self._files),
                ", ".join(servers),
            )

    def restore(self) -> None:
        for path in self._files:
            try:
                os.unlink(path)
            except OSError as exc:
                logger.warning("cannot remove %s: %s", path, exc)
        self._files.clear()
        for service, previous in self._services:
            arguments = previous if previous else ["empty"]
            subprocess.run(
                ["networksetup", "-setdnsservers", service] + arguments,
                capture_output=True,
            )
        self._services.clear()
        self._flush()

    @staticmethod
    def _flush() -> None:
        subprocess.run(["dscacheutil", "-flushcache"], capture_output=True)
        subprocess.run(["killall", "-HUP", "mDNSResponder"], capture_output=True)

    @property
    def state(self) -> dict:
        return {
            "services": [[service, list(previous)] for service, previous in self._services],
            "files": list(self._files),
        }

    @classmethod
    def from_state(cls, entries: dict) -> "Resolver":
        resolver = cls()
        resolver._services = [
            (service, list(previous)) for service, previous in entries.get("services", [])
        ]
        resolver._files = list(entries.get("files", []))
        return resolver

    @staticmethod
    def _network_services() -> list[str]:
        """Services backed by an interface that is currently up.

        Every VPN client on the machine registers a network service of its own,
        and inactive adapters stay in the list forever. Setting DNS on those
        does nothing useful, and whatever is left there survives long after
        this tunnel is gone.
        """
        services = []
        name = None
        for line in _output(["networksetup", "-listnetworkserviceorder"]).splitlines():
            line = line.strip()
            if line.startswith("(Hardware Port:"):
                device = line.rstrip(")").rsplit("Device:", 1)[-1].strip()
                if name and device and "inet " in _output(["ifconfig", device]):
                    services.append(name)
                name = None
            elif line.startswith("(") and ") " in line:
                name = line.split(") ", 1)[1]
        return services

    @staticmethod
    def _current(service: str) -> list[str]:
        output = _output(["networksetup", "-getdnsservers", service]).split()
        return [] if not output or "any" in output[0].lower() else output


def save_state(interface: str, server: str, routes: Routes, resolver: Resolver | None) -> None:
    state = {
        "pid": os.getpid(),
        "interface": interface,
        "server": server,
        "routes": routes.state if routes else [],
        "dns": resolver.state if resolver else {},
    }
    try:
        with open(STATE_FILE, "w") as handle:
            json.dump(state, handle)
    except OSError as exc:
        logger.warning("cannot record network state in %s: %s", STATE_FILE, exc)


def load_state() -> dict | None:
    try:
        with open(STATE_FILE) as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return None


def clear_state() -> None:
    try:
        os.unlink(STATE_FILE)
    except OSError:
        pass


def restore_state(state: dict) -> None:
    # A failure in one half must not leave the other half applied: whatever is
    # left behind is what cuts the machine off the network.
    try:
        Resolver.from_state(state.get("dns", {})).restore()
    except Exception as exc:
        logger.error("cannot restore DNS: %s", exc)
    Routes.from_state(state.get("routes", [])).withdraw()


def recover_leftovers() -> None:
    """Undo what a run that was killed instead of stopped left behind.

    Must happen before a new tunnel records its own state: save_state
    overwrites the file, and the lost record is the only description of what
    the machine looked like before anything was touched.
    """
    state = load_state()
    if state is None:
        return
    pid = state.get("pid", 0)
    if pid and pid != os.getpid() and process_alive(pid):
        return
    logger.warning(
        "a previous run left %s redirected; restoring routes and DNS",
        state.get("interface", "the network"),
    )
    restore_state(state)
    clear_state()


def process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True
