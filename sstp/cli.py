from __future__ import annotations

import argparse
import getpass
import os
import shutil
import signal
import subprocess
import sys
import time
from xml.sax.saxutils import escape

from . import daemon, ipc, log, net
from .session import Config, Session, SessionError
from .token import Token, TokenError, discover_modules


def _add_token_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--pkcs11-module",
        help="path to the PKCS#11 library (autodetected when omitted)",
    )
    parser.add_argument("--slot", type=int, help="PKCS#11 slot number")
    parser.add_argument(
        "--pin-stdin",
        action="store_true",
        help="read the PIN from stdin instead of prompting",
    )
    parser.add_argument(
        "--cert",
        help="certificate to authenticate with: index, CKA_ID hex, or part of the subject",
    )


def _open_token(args) -> Token:
    """Open a session without logging in; the PIN is only needed to sign."""
    token = Token(args.pkcs11_module)
    token.open(slot=args.slot)
    return token


def _read_pin(args, token: Token) -> str:
    # Never accept the PIN as an argument: argv is visible to every process.
    if args.pin_stdin:
        pin = sys.stdin.readline().rstrip("\n")
        if not pin:
            raise SystemExit("no PIN was supplied on stdin")
        return pin
    return getpass.getpass(f"PIN for {token.info.label or token.module_path}: ")


def _select_certificate(certificates, selector: str | None):
    if not certificates:
        raise SystemExit("no certificates were found on the token")
    if selector is None:
        if len(certificates) == 1:
            return certificates[0]
        raise SystemExit(
            "several certificates are available; choose one with --cert "
            "(run the 'list' command to see them)"
        )
    if selector.isdigit() and int(selector) < len(certificates):
        return certificates[int(selector)]
    lowered = selector.lower()
    for entry in certificates:
        if entry.ckaid.hex() == lowered or lowered in entry.subject.lower():
            return entry
        if entry.label and lowered in entry.label.lower():
            return entry
    raise SystemExit(f"no certificate matches {selector!r}")


def command_list(args) -> int:
    token = _open_token(args)
    try:
        certificates = token.certificates()
        if not certificates:
            print("no certificates on this token")
            return 1
        print(f"token: {token.info.label} (serial {token.info.serial})")

        # Indices must stay stable whether or not the filter is on, so that a
        # --cert taken from this listing keeps meaning the same certificate.
        shown = [
            (index, entry)
            for index, entry in enumerate(certificates)
            if args.all or entry.is_suitable
        ]
        for index, entry in shown:
            notes = []
            if entry.is_expired:
                notes.append("EXPIRED")
            if entry.is_self_signed:
                notes.append("self-signed")
            if not entry.can_authenticate:
                notes.append("not for authentication")
            if not entry.principal_name():
                notes.append("no UPN")
            suffix = f"  <- {', '.join(notes)}" if notes else ""
            print(f"\n[{index}] {entry.label or '(no label)'}{suffix}")
            print(f"     subject : {entry.subject}")
            print(f"     issuer  : {entry.issuer}")
            print(f"     CKA_ID  : {entry.ckaid.hex()}")
            print(f"     UPN     : {entry.principal_name() or '-'}")
            print(f"     expires : {entry.certificate.not_valid_after_utc:%Y-%m-%d}")

        hidden = len(certificates) - len(shown)
        if hidden:
            print(f"\n{hidden} certificate(s) hidden; use --all to see them")

        suitable = [
            index for index, entry in enumerate(certificates) if entry.is_suitable
        ]
        if not suitable:
            print("\nno certificate on this token can be used for authentication")
            return 1
        print("\nuse: " + ", ".join(f"--cert {index}" for index in suitable))
        return 0
    finally:
        token.close()


def command_modules(args) -> int:
    found = discover_modules()
    if not found:
        print("no known PKCS#11 module found")
        return 1
    for path in found:
        print(path)
    return 0


def command_connect(args) -> int:
    if os.geteuid() != 0:
        print("the tunnel needs root privileges; run with sudo", file=sys.stderr)
        return 1

    net.recover_leftovers()
    token = _open_token(args)
    try:
        chosen = _select_certificate(token.certificates(), args.cert)
        if not chosen.can_authenticate:
            print(
                f"error: {chosen.subject} is not marked for client authentication "
                f"(EKU {', '.join(chosen.extended_key_usage or [])}); "
                "the server will reject it",
                file=sys.stderr,
            )
            return 1
        if chosen.is_expired:
            print(
                f"error: certificate expired on "
                f"{chosen.certificate.not_valid_after_utc:%Y-%m-%d}; "
                "the server will reject it",
                file=sys.stderr,
            )
            return 1
        token.login(_read_pin(args, token))
        identity = token.identity_for(chosen)
        print(f"authenticating as: {identity.subject}")

        config = Config(
            server=args.server,
            port=args.port,
            username=args.username or "",
            ca_file=args.ca_file,
            verify_outer=not args.no_verify,
            verify_inner=not args.no_verify_inner,
            inner_ca_file=args.inner_ca_file or args.ca_file,
            mtu=args.mtu,
            default_route=not args.no_default_route,
            set_dns=not args.no_dns,
            extra_routes=args.route or [],
            dns_domains=args.dns_domain or [],
        )
        session = Session(config, token, identity)
        signal.signal(signal.SIGINT, lambda *_: session.stop())
        signal.signal(signal.SIGTERM, lambda *_: session.stop())

        session.connect()
        session.run()
        return 0
    except (SessionError, TokenError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        token.close()


def command_daemon(args) -> int:
    if os.geteuid() != 0:
        print("the daemon needs root privileges; run with sudo", file=sys.stderr)
        return 1
    service = daemon.Daemon(args.socket)
    signal.signal(signal.SIGINT, lambda *_: service.stop())
    signal.signal(signal.SIGTERM, lambda *_: service.stop())
    try:
        service.serve()
    except daemon.DaemonError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


LAUNCHD_LABEL = "local.sstp.daemon"
LAUNCHD_PLIST = f"/Library/LaunchDaemons/{LAUNCHD_LABEL}.plist"

LAUNCHD_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" \
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>              <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{python}</string>
        <string>-m</string>
        <string>sstp</string>
        <string>daemon</string>
        <string>--socket</string>
        <string>{socket}</string>
    </array>
    <key>WorkingDirectory</key>   <string>{workdir}</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>           <string>/usr/bin:/bin:/usr/sbin:/sbin</string>
    </dict>
    <key>RunAtLoad</key>          <true/>
    <key>KeepAlive</key>          <true/>
    <key>StandardOutPath</key>    <string>/var/log/sstp.log</string>
    <key>StandardErrorPath</key>  <string>/var/log/sstp.log</string>
</dict>
</plist>
"""


def _launchctl(*arguments: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["launchctl", *arguments], capture_output=True, text=True
    )


def _stop_service() -> None:
    """Unload the job and wait for launchd to finish with it.

    bootout returns before the job is really gone, and a bootstrap that lands
    in that window fails with 'Input/output error'.
    """
    _launchctl("bootout", f"system/{LAUNCHD_LABEL}")
    for _ in range(50):
        if _launchctl("print", f"system/{LAUNCHD_LABEL}").returncode != 0:
            return
        time.sleep(0.1)


INSTALL_ROOT = "/usr/local/libexec/sstp"


def _bundled_payload() -> str | None:
    """The app bundle's Resources directory, when running from inside one.

    Recognised by an interpreter sitting next to the package; a development
    checkout keeps its virtualenv elsewhere.
    """
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if os.path.exists(os.path.join(root, "python", "bin", "python3")):
        return root
    return None


def _install_payload(source: str) -> str:
    """Copy the runtime and the package where only root can rewrite them.

    launchd starts the daemon as root, and the app bundle belongs to whoever
    installed it: running from there would let anything with that user's rights
    replace the code root executes on the next boot.
    """
    if os.path.exists(INSTALL_ROOT):
        shutil.rmtree(INSTALL_ROOT)
    os.makedirs(INSTALL_ROOT, exist_ok=True)
    for name in ("python", "sstp"):
        # ditto rather than copytree: the runtime is held together by symlinks.
        subprocess.run(
            ["ditto", os.path.join(source, name), os.path.join(INSTALL_ROOT, name)],
            check=True,
        )
    subprocess.run(["chown", "-R", "root:wheel", INSTALL_ROOT], check=True)
    subprocess.run(["chmod", "-R", "go-w", INSTALL_ROOT], check=True)
    return INSTALL_ROOT


def command_install(args) -> int:
    if os.geteuid() != 0:
        print("installing a system daemon needs root; run with sudo", file=sys.stderr)
        return 1

    bundle = _bundled_payload()
    if bundle is not None:
        package_root = _install_payload(bundle)
        python = os.path.join(package_root, "python", "bin", "python3")
    else:
        package_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        python = sys.executable

    plist = LAUNCHD_TEMPLATE.format(
        label=LAUNCHD_LABEL,
        python=escape(python),
        socket=escape(args.socket),
        workdir=escape(package_root),
    )
    _stop_service()
    with open(LAUNCHD_PLIST, "w") as handle:
        handle.write(plist)
    os.chown(LAUNCHD_PLIST, 0, 0)
    os.chmod(LAUNCHD_PLIST, 0o644)

    result = _launchctl("bootstrap", "system", LAUNCHD_PLIST)
    if result.returncode != 0:
        print(f"launchctl bootstrap failed: {result.stderr.strip()}", file=sys.stderr)
        return 1
    print(f"installed {LAUNCHD_PLIST} running {python}")
    print(f"logs: /var/log/sstp.log, socket: {args.socket}")
    return 0


def command_uninstall(args) -> int:
    if os.geteuid() != 0:
        print("removing a system daemon needs root; run with sudo", file=sys.stderr)
        return 1
    _stop_service()
    shutil.rmtree(INSTALL_ROOT, ignore_errors=True)
    try:
        os.unlink(LAUNCHD_PLIST)
    except FileNotFoundError:
        print("the daemon was not installed")
        return 1
    print(f"removed {LAUNCHD_PLIST}")
    return 0


def command_status(args) -> int:
    state = net.load_state()
    if state is None:
        print("no tunnel is active")
        return 1
    pid = state.get("pid", 0)
    alive = net.process_alive(pid) if pid else False
    print(f"server    : {state.get('server', '?')}")
    print(f"interface : {state.get('interface', '?')}")
    print(f"client pid: {pid} ({'running' if alive else 'GONE'})")
    print(f"routes    : {len(state.get('routes', []))} added")
    dns = state.get("dns", {})
    print(f"DNS       : {len(dns.get('services', []))} services, "
          f"{len(dns.get('files', []))} resolver files")
    if not alive:
        print("\nthe client is gone but the network is still redirected; "
              "run 'sstp disconnect' to restore it")
    return 0


def command_disconnect(args) -> int:
    state = net.load_state()
    if state is None:
        print("no tunnel is active")
        return 1
    if os.geteuid() != 0:
        print("restoring routes and DNS needs root; run with sudo", file=sys.stderr)
        return 1

    pid = state.get("pid", 0)
    if pid and net.process_alive(pid):
        os.kill(pid, signal.SIGTERM)
        print(f"asked the client (pid {pid}) to disconnect")
        # It restores the network itself, which keeps the teardown ordered.
        for _ in range(100):
            if not net.process_alive(pid):
                print("disconnected")
                return 0
            time.sleep(0.1)
        print("the client did not exit; restoring settings directly", file=sys.stderr)

    net.restore_state(state)
    net.clear_state()
    print("routes and DNS restored")
    return 0


def main(argv=None) -> int:
    # Shared so that -v works both before and after the subcommand.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-v", "--verbose", action="store_true", help="debug logging")

    parser = argparse.ArgumentParser(
        prog="sstp",
        parents=[common],
        description="SSTP VPN client with smart card authentication",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    modules = subparsers.add_parser(
        "modules", parents=[common], help="list detected PKCS#11 modules"
    )
    modules.set_defaults(handler=command_modules)

    listing = subparsers.add_parser(
        "list", parents=[common], help="list certificates on the token"
    )
    listing.add_argument(
        "--all",
        action="store_true",
        help="include certificates that cannot be used for authentication",
    )
    _add_token_arguments(listing)
    listing.set_defaults(handler=command_list)

    connect = subparsers.add_parser(
        "connect", parents=[common], help="establish the VPN tunnel"
    )
    connect.add_argument("server", help="SSTP server hostname")
    connect.add_argument("--port", type=int, default=443)
    connect.add_argument("--username", help="EAP identity (defaults to the UPN)")
    connect.add_argument("--ca-file", help="CA bundle for the server certificate")
    connect.add_argument("--inner-ca-file", help="CA bundle for the EAP-TLS server")
    connect.add_argument(
        "--no-verify", action="store_true", help="skip outer TLS verification"
    )
    connect.add_argument(
        "--no-verify-inner", action="store_true", help="skip EAP-TLS verification"
    )
    connect.add_argument("--mtu", type=int, default=1400)
    connect.add_argument(
        "--no-default-route", action="store_true", help="do not route all traffic"
    )
    connect.add_argument("--no-dns", action="store_true", help="do not change DNS")
    connect.add_argument(
        "--route", action="append", help="extra network to route (repeatable)"
    )
    connect.add_argument(
        "--dns-domain",
        action="append",
        help="resolve only this domain through the tunnel (repeatable); "
        "by default every lookup goes to the tunnel's DNS servers",
    )
    _add_token_arguments(connect)
    connect.set_defaults(handler=command_connect)

    service = subparsers.add_parser(
        "daemon", parents=[common], help="run the privileged control daemon"
    )
    service.add_argument("--socket", default=ipc.SOCKET_PATH)
    service.set_defaults(handler=command_daemon)

    install = subparsers.add_parser(
        "install", parents=[common], help="install the daemon into launchd"
    )
    install.add_argument("--socket", default=ipc.SOCKET_PATH)
    install.set_defaults(handler=command_install)

    uninstall = subparsers.add_parser(
        "uninstall", parents=[common], help="remove the launchd daemon"
    )
    uninstall.set_defaults(handler=command_uninstall)

    status = subparsers.add_parser(
        "status", parents=[common], help="show the active tunnel"
    )
    status.set_defaults(handler=command_status)

    disconnect = subparsers.add_parser(
        "disconnect",
        parents=[common],
        help="stop the tunnel and restore routes and DNS",
    )
    disconnect.set_defaults(handler=command_disconnect)

    args = parser.parse_args(argv)
    log.setup(args.verbose)
    try:
        return args.handler(args)
    except TokenError as exc:
        print(f"token error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
