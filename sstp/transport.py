"""Outer transport: TLS connection to the server and SSTP packet framing.

SSTP runs a single long-lived HTTP request over TLS. The client sends an
SSTP_DUPLEX_POST with an absurd Content-Length, the server answers 200, and
from that point both directions carry raw SSTP packets.
"""

from __future__ import annotations

import socket
import ssl
import uuid

from . import log, protocol, trust

logger = log.get("transport")

# The server never reads this many bytes; it is the conventional value that
# keeps the HTTP layer from ever terminating the request.
CONTENT_LENGTH = "18446744073709551615"


class TransportError(Exception):
    pass


class Transport:
    def __init__(
        self,
        host: str,
        port: int = 443,
        ca_file: str | None = None,
        verify: bool = True,
        timeout: float = 30.0,
    ):
        self.host = host
        self.port = port
        self.ca_file = ca_file
        self.verify = verify
        self.timeout = timeout
        self.sock: ssl.SSLSocket | None = None
        self.server_cert_der: bytes | None = None
        self._buffer = bytearray()

    def _context(self) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        if self.verify:
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            if self.ca_file:
                context.load_verify_locations(cafile=self.ca_file)
            else:
                context.load_default_certs(ssl.Purpose.SERVER_AUTH)
                # Enterprise CAs are deployed to the keychain, which ssl ignores.
                anchors = trust.system_anchors()
                if anchors:
                    context.load_verify_locations(cadata=anchors)
        else:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            logger.warning(
                "TLS certificate verification is DISABLED — use only for diagnostics"
            )
        return context

    def connect(self) -> None:
        try:
            raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
        except socket.gaierror as exc:
            raise TransportError(
                f"cannot resolve {self.host}: {exc}. Check the name, and that "
                "no other VPN has taken over DNS"
            ) from exc
        except OSError as exc:
            raise TransportError(
                f"cannot reach {self.host}:{self.port}: {exc}"
            ) from exc
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sock = self._context().wrap_socket(raw, server_hostname=self.host)
        self.server_cert_der = self.sock.getpeercert(binary_form=True)
        logger.info(
            "TLS established with %s:%s (%s)",
            self.host,
            self.port,
            self.sock.version(),
        )
        self._http_handshake()

    def _http_handshake(self) -> None:
        correlation_id = "{%s}" % str(uuid.uuid4()).upper()
        request = (
            f"SSTP_DUPLEX_POST {protocol.SSTP_URI} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"SSTPCORRELATIONID: {correlation_id}\r\n"
            f"Content-Length: {CONTENT_LENGTH}\r\n"
            "\r\n"
        )
        self.sock.sendall(request.encode("ascii"))

        header = bytearray()
        while b"\r\n\r\n" not in header:
            chunk = self.sock.recv(1)
            if not chunk:
                raise TransportError("server closed connection during HTTP handshake")
            header += chunk
            if len(header) > 8192:
                raise TransportError("HTTP response header too long")

        status_line = header.split(b"\r\n", 1)[0].decode("latin-1")
        logger.debug("HTTP response: %s", status_line)
        if " 200" not in status_line:
            raise TransportError(f"server rejected SSTP request: {status_line}")
        logger.info("SSTP HTTP layer established")

    def send(self, data: bytes) -> None:
        if self.sock is None:
            raise TransportError("not connected")
        self.sock.sendall(data)

    def send_control(self, packet: protocol.ControlPacket) -> None:
        logger.debug("send %s", packet)
        self.send(packet.encode())

    def send_data(self, ppp_frame: bytes) -> None:
        self.send(protocol.encode_data_packet(ppp_frame))

    def fileno(self) -> int:
        return self.sock.fileno()

    def read_packets(self) -> list[tuple[bool, bytes]]:
        """Read whatever is available and return complete packets.

        Returns a list of (is_control, payload) where payload excludes the
        4-byte SSTP header. Raises TransportError when the peer closes.
        """
        if self.sock is None:
            raise TransportError("not connected")
        chunk = self.sock.recv(65536)
        if not chunk:
            raise TransportError("connection closed by server")
        self._buffer += chunk
        # A single TLS read can leave more decrypted data buffered inside the
        # SSL object; drain it so select() does not stall waiting for traffic.
        while self.sock.pending():
            self._buffer += self.sock.recv(self.sock.pending())

        packets = []
        while len(self._buffer) >= protocol.HEADER_LEN:
            is_control, length = protocol.parse_header(bytes(self._buffer))
            if len(self._buffer) < length:
                break
            payload = bytes(self._buffer[protocol.HEADER_LEN : length])
            del self._buffer[:length]
            packets.append((is_control, payload))
        return packets

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None
