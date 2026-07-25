"""Session orchestration: SSTP control plane, PPP negotiation and the tunnel."""

from __future__ import annotations

import selectors
import time
from dataclasses import dataclass, field

from . import crypto_binding, log, net, protocol
from .ppp import decode_frame, encode_frame, frame, ipcp, lcp
from .ppp.eap import EapAuthenticator
from .transport import Transport, TransportError

logger = log.get("session")

NEGOTIATION_TIMEOUT = 60.0
RETRANSMIT_INTERVAL = 3.0
MAX_RETRANSMITS = 10


@dataclass
class Config:
    server: str
    port: int = 443
    username: str = ""
    ca_file: str | None = None
    verify_outer: bool = True
    verify_inner: bool = True
    inner_ca_file: str | None = None
    mtu: int = 1400
    default_route: bool = True
    set_dns: bool = True
    pkcs11_module: str | None = None
    slot: int | None = None
    extra_routes: list[str] = field(default_factory=list)
    dns_domains: list[str] = field(default_factory=list)


class SessionError(Exception):
    pass


class Session:
    def __init__(self, config: Config, token, identity, on_event=None):
        self.config = config
        self.token = token
        self.identity = identity
        self._on_event = on_event

        self.transport = Transport(
            config.server,
            config.port,
            ca_file=config.ca_file,
            verify=config.verify_outer,
        )
        self.lcp = lcp.Lcp(self._send_ppp, mru=config.mtu)
        self.ipcp = ipcp.Ipcp(self._send_ppp)
        self.eap: EapAuthenticator | None = None

        self.utun: net.Utun | None = None
        self.routes: net.Routes | None = None
        self.resolver: net.Resolver | None = None

        self._nonce = b""
        self._hash_protocol = 0
        self._call_connected_sent = False
        self._auth_started = False
        self._ipcp_started = False
        self._tunnel_up = False
        self._running = False
        self._closed = False
        self._deadline = 0.0
        self._last_retransmit = 0.0
        self._retransmits = 0

    # ------------------------------------------------------------------ setup

    def _emit(self, name: str, **fields) -> None:
        if self._on_event is not None:
            self._on_event(name, **fields)

    def _send_ppp(self, protocol_number: int, payload: bytes) -> None:
        self.transport.send_data(encode_frame(protocol_number, payload))

    def connect(self) -> None:
        self.transport.connect()
        self._send_connect_request()
        self._deadline = time.time() + NEGOTIATION_TIMEOUT

    def _send_connect_request(self) -> None:
        attribute = protocol.Attribute(
            protocol.ATTR_ENCAPSULATED_PROTOCOL_ID,
            protocol.PROTOCOL_ID_PPP.to_bytes(2, "big"),
        )
        self.transport.send_control(
            protocol.ControlPacket(protocol.MSG_CALL_CONNECT_REQUEST, [attribute])
        )
        logger.info("sent Call Connect Request")

    # ------------------------------------------------------------- main loop

    def run(self) -> None:
        self._running = True
        self._selector = selectors.DefaultSelector()
        self._selector.register(self.transport.sock, selectors.EVENT_READ, "sstp")
        try:
            while self._running:
                for key, _ in self._selector.select(timeout=1.0):
                    if key.data == "sstp":
                        self._drain_transport()
                    else:
                        self._forward_outbound()
                self._tick()
        finally:
            self._selector.close()
            self.shutdown()

    def _drain_transport(self) -> None:
        try:
            packets = self.transport.read_packets()
        except TransportError as exc:
            logger.error("%s", exc)
            self._running = False
            return
        for is_control, payload in packets:
            if is_control:
                self._handle_control(protocol.parse_control(payload))
            else:
                self._handle_ppp(payload)

    def _forward_outbound(self) -> None:
        packet = self.utun.read()
        if packet:
            self._send_ppp(frame.PPP_IP, packet)

    def _tick(self) -> None:
        now = time.time()
        if not self._tunnel_up and self._deadline and now > self._deadline:
            raise SessionError("negotiation timed out")
        # Retransmit an unanswered Configure-Request.
        if now - self._last_retransmit >= RETRANSMIT_INTERVAL:
            self._last_retransmit = now
            if self._auth_started and not self.lcp.is_open:
                self._retransmit(self.lcp)
            elif self._ipcp_started and not self.ipcp.is_open:
                self._retransmit(self.ipcp)

    def _retransmit(self, machine) -> None:
        self._retransmits += 1
        if self._retransmits > MAX_RETRANSMITS:
            raise SessionError(f"{machine.name} negotiation failed (no response)")
        machine.send_configure_request()

    # -------------------------------------------------------------- control

    def _handle_control(self, packet: protocol.ControlPacket) -> None:
        logger.debug("recv %s", packet)
        if packet.message_type == protocol.MSG_CALL_CONNECT_ACK:
            self._on_connect_ack(packet)
        elif packet.message_type == protocol.MSG_ECHO_REQUEST:
            self.transport.send_control(
                protocol.ControlPacket(protocol.MSG_ECHO_RESPONSE, [])
            )
        elif packet.message_type == protocol.MSG_CALL_CONNECT_NAK:
            status = packet.find(protocol.ATTR_STATUS_INFO)
            detail = protocol.status_text(status) if status else "no detail"
            raise SessionError(f"server refused the connection: {detail}")
        elif packet.message_type in (
            protocol.MSG_CALL_ABORT,
            protocol.MSG_CALL_DISCONNECT,
        ):
            status = packet.find(protocol.ATTR_STATUS_INFO)
            detail = protocol.status_text(status) if status else "no detail"
            logger.error("server closed the call: %s", detail)
            self.transport.send_control(
                protocol.ControlPacket(protocol.MSG_CALL_DISCONNECT_ACK, [])
            )
            self._running = False

    def _on_connect_ack(self, packet: protocol.ControlPacket) -> None:
        value = packet.find(protocol.ATTR_CRYPTO_BINDING_REQ)
        if value is None:
            raise SessionError("Call Connect Ack without a crypto binding request")
        self._hash_protocol, self._nonce = crypto_binding.parse_binding_request(value)
        logger.info(
            "Call Connect Ack accepted (hash protocol bitmask 0x%02x)",
            self._hash_protocol,
        )
        self._auth_started = True
        self._last_retransmit = time.time()
        self.lcp.send_configure_request()

    # ------------------------------------------------------------------ PPP

    def _handle_ppp(self, data: bytes) -> None:
        protocol_number, payload = decode_frame(data)

        if protocol_number == frame.PPP_LCP:
            was_open = self.lcp.is_open
            self.lcp.handle(payload)
            if self.lcp.terminated:
                self._running = False
            elif self.lcp.is_open and not was_open:
                logger.info("LCP is up")
                self._retransmits = 0
                self._start_authentication()
        elif protocol_number == frame.PPP_EAP:
            self._handle_eap(payload)
        elif protocol_number == frame.PPP_IPCP:
            was_open = self.ipcp.is_open
            self.ipcp.handle(payload)
            if self.ipcp.is_open and not was_open:
                self._bring_up_tunnel()
        elif protocol_number == frame.PPP_IP:
            if self.utun is not None:
                self.utun.write(payload)
        else:
            logger.debug("rejecting PPP protocol 0x%04x", protocol_number)
            self.lcp._emit(
                frame.CODE_PROTOCOL_REJECT,
                self.lcp._next_identifier(),
                protocol_number.to_bytes(2, "big") + payload,
            )

    def _start_authentication(self) -> None:
        if self.eap is not None:
            return
        username = self.config.username or self.identity.principal_name() or ""
        if not username:
            raise SessionError(
                "no EAP identity: the certificate has no UPN, pass --username"
            )
        self.eap = EapAuthenticator(
            self.identity,
            self.token,
            username,
            self._send_ppp,
            server_name=self.config.server,
            ca_file=self.config.inner_ca_file,
            verify=self.config.verify_inner,
        )

    def _handle_eap(self, payload: bytes) -> None:
        if self.eap is None:
            self._start_authentication()
        self.eap.handle(payload)
        if self.eap.failed:
            raise SessionError("EAP-TLS authentication was rejected by the server")
        if self.eap.succeeded and not self._call_connected_sent:
            self._send_call_connected()

    def _send_call_connected(self) -> None:
        hlak = crypto_binding.hlak_from_msk(self.eap.msk)
        packet = crypto_binding.build_call_connected(
            hlak, self._nonce, self.transport.server_cert_der, self._hash_protocol
        )
        self.transport.send(packet)
        self._call_connected_sent = True
        logger.info("sent Call Connected with crypto binding")

        self._ipcp_started = True
        self._retransmits = 0
        self._last_retransmit = time.time()
        self.ipcp.send_configure_request()

    # --------------------------------------------------------------- tunnel

    def _bring_up_tunnel(self) -> None:
        local = self.ipcp.local_address
        peer = self.ipcp.peer_address or "10.0.0.1"
        if not local:
            raise SessionError("server did not assign an IP address")

        self.utun = net.Utun()
        name = self.utun.open()
        net.configure_interface(name, local, peer, self.config.mtu)

        if self.config.default_route:
            self.routes = net.redirect_default(name, peer, self.transport.host)
        else:
            self.routes = net.Routes()
        for destination in self.config.extra_routes:
            self.routes.add(destination, peer, name)

        if self.config.set_dns:
            if not self.config.default_route:
                # The DNS servers sit inside the corporate network: without a
                # route of their own every lookup goes out the physical link
                # and times out.
                for server in self.ipcp.dns_servers:
                    self.routes.add_host(server, interface=name)
            self.resolver = net.Resolver()
            self.resolver.apply(self.ipcp.dns_servers, self.config.dns_domains)

        net.save_state(name, self.transport.host, self.routes, self.resolver)

        self._selector.register(self.utun, selectors.EVENT_READ, "utun")
        self._tunnel_up = True
        self._deadline = 0.0
        logger.info(
            "tunnel is up: %s address %s, DNS %s",
            name,
            local,
            ", ".join(self.ipcp.dns_servers) or "unchanged",
        )
        self._emit(
            "connected",
            interface=name,
            address=local,
            peer=peer,
            dns=list(self.ipcp.dns_servers),
        )

    def _safely(self, description: str, action) -> None:
        """Run one teardown step; a failure must not strand the others.

        Leaving the default route or DNS pointing at a dead tunnel would cut the
        machine off the network entirely, so every step gets its own attempt.
        """
        try:
            action()
        except Exception as exc:
            logger.error("%s failed: %s", description, exc)

    def shutdown(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self.resolver is not None:
            self._safely("restoring DNS", self.resolver.restore)
            self.resolver = None
        if self.routes is not None:
            self._safely("withdrawing routes", self.routes.withdraw)
            self.routes = None
        if self.utun is not None:
            self._safely("closing the tunnel interface", self.utun.close)
            self.utun = None
        self._safely(
            "sending Call Disconnect",
            lambda: self.transport.send_control(
                protocol.ControlPacket(protocol.MSG_CALL_DISCONNECT, [])
            ),
        )
        self._safely("closing the transport", self.transport.close)
        net.clear_state()
        logger.info("session closed")

    def stop(self) -> None:
        self._running = False
