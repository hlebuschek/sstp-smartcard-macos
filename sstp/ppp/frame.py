"""PPP framing and the option negotiation state machine.

Inside SSTP a PPP frame is carried without HDLC: no flag bytes, no byte
stuffing and no FCS. What remains is the address/control pair followed by the
protocol number and the payload.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .. import log

logger = log.get("ppp")

PPP_IP = 0x0021
PPP_IPV6 = 0x0057
PPP_IPCP = 0x8021
PPP_IPV6CP = 0x8057
PPP_CCP = 0x80FD
PPP_LCP = 0xC021
PPP_PAP = 0xC023
PPP_CHAP = 0xC223
PPP_EAP = 0xC227

# Configuration protocol codes (RFC 1661)
CODE_CONFIGURE_REQUEST = 1
CODE_CONFIGURE_ACK = 2
CODE_CONFIGURE_NAK = 3
CODE_CONFIGURE_REJECT = 4
CODE_TERMINATE_REQUEST = 5
CODE_TERMINATE_ACK = 6
CODE_CODE_REJECT = 7
CODE_PROTOCOL_REJECT = 8
CODE_ECHO_REQUEST = 9
CODE_ECHO_REPLY = 10
CODE_DISCARD_REQUEST = 11

CODE_NAMES = {
    CODE_CONFIGURE_REQUEST: "Configure-Request",
    CODE_CONFIGURE_ACK: "Configure-Ack",
    CODE_CONFIGURE_NAK: "Configure-Nak",
    CODE_CONFIGURE_REJECT: "Configure-Reject",
    CODE_TERMINATE_REQUEST: "Terminate-Request",
    CODE_TERMINATE_ACK: "Terminate-Ack",
    CODE_CODE_REJECT: "Code-Reject",
    CODE_PROTOCOL_REJECT: "Protocol-Reject",
    CODE_ECHO_REQUEST: "Echo-Request",
    CODE_ECHO_REPLY: "Echo-Reply",
    CODE_DISCARD_REQUEST: "Discard-Request",
}


class PppError(Exception):
    pass


def encode_frame(protocol_number: int, payload: bytes) -> bytes:
    return b"\xff\x03" + struct.pack("!H", protocol_number) + payload


def decode_frame(frame: bytes) -> tuple[int, bytes]:
    """Return (protocol, payload), tolerating omitted address/control bytes."""
    offset = 0
    if len(frame) >= 2 and frame[0] == 0xFF and frame[1] == 0x03:
        offset = 2
    if len(frame) < offset + 2:
        raise PppError(f"short PPP frame ({len(frame)} bytes)")
    # A protocol number always has its low bit set in the last byte; a single
    # odd byte means protocol field compression is in use.
    if frame[offset] & 0x01:
        return frame[offset], frame[offset + 1 :]
    (protocol_number,) = struct.unpack("!H", frame[offset : offset + 2])
    return protocol_number, frame[offset + 2 :]


@dataclass
class Packet:
    code: int
    identifier: int
    data: bytes

    def encode(self) -> bytes:
        return struct.pack("!BBH", self.code, self.identifier, len(self.data) + 4) + self.data

    @property
    def name(self) -> str:
        return CODE_NAMES.get(self.code, f"code {self.code}")


def decode_packet(payload: bytes) -> Packet:
    if len(payload) < 4:
        raise PppError("short configuration packet")
    code, identifier, length = struct.unpack("!BBH", payload[:4])
    if length < 4 or length > len(payload):
        length = len(payload)
    return Packet(code, identifier, payload[4:length])


def encode_options(options: dict[int, bytes]) -> bytes:
    out = bytearray()
    for option_type, value in options.items():
        out += struct.pack("!BB", option_type, len(value) + 2) + value
    return bytes(out)


def decode_options(data: bytes) -> dict[int, bytes]:
    options: dict[int, bytes] = {}
    offset = 0
    while offset + 2 <= len(data):
        option_type, length = struct.unpack("!BB", data[offset : offset + 2])
        if length < 2 or offset + length > len(data):
            raise PppError(f"malformed option {option_type} (length {length})")
        options[option_type] = data[offset + 2 : offset + length]
        offset += length
    return options


@dataclass
class ConfigureFsm:
    """Option negotiation for a configuration protocol such as LCP or IPCP.

    Only the parts of RFC 1661 that a client needs are implemented: both
    directions must reach Configure-Ack before the layer is considered open.
    """

    protocol_number: int
    name: str
    send: object  # callable(protocol_number, payload)
    local_ack: bool = False
    remote_ack: bool = False
    identifier: int = 0
    options: dict[int, bytes] = field(default_factory=dict)
    peer_options: dict[int, bytes] = field(default_factory=dict)
    _rejected: set[int] = field(default_factory=set)

    @property
    def is_open(self) -> bool:
        return self.local_ack and self.remote_ack

    def reset(self) -> None:
        self.local_ack = False
        self.remote_ack = False
        self._rejected.clear()

    def _next_identifier(self) -> int:
        self.identifier = (self.identifier + 1) & 0xFF
        return self.identifier

    def _emit(self, code: int, identifier: int, data: bytes) -> None:
        packet = Packet(code, identifier, data)
        logger.debug("%s send %s id=%d", self.name, packet.name, identifier)
        self.send(self.protocol_number, packet.encode())

    def send_configure_request(self) -> None:
        payload = encode_options(
            {k: v for k, v in self.options.items() if k not in self._rejected}
        )
        self._emit(CODE_CONFIGURE_REQUEST, self._next_identifier(), payload)

    def handle(self, payload: bytes) -> Packet:
        packet = decode_packet(payload)
        logger.debug("%s recv %s id=%d", self.name, packet.name, packet.identifier)

        if packet.code == CODE_CONFIGURE_REQUEST:
            self._handle_request(packet)
        elif packet.code == CODE_CONFIGURE_ACK:
            self.local_ack = True
        elif packet.code == CODE_CONFIGURE_NAK:
            self._handle_nak(packet)
        elif packet.code == CODE_CONFIGURE_REJECT:
            self._handle_reject(packet)
        return packet

    def _handle_request(self, packet: Packet) -> None:
        options = decode_options(packet.data)
        rejected = {}
        nakked = {}
        for option_type, value in options.items():
            verdict, replacement = self.review_peer_option(option_type, value)
            if verdict == "reject":
                rejected[option_type] = value
            elif verdict == "nak":
                nakked[option_type] = replacement

        if rejected:
            self._emit(
                CODE_CONFIGURE_REJECT, packet.identifier, encode_options(rejected)
            )
            return
        if nakked:
            self._emit(CODE_CONFIGURE_NAK, packet.identifier, encode_options(nakked))
            return

        self.peer_options = options
        self.remote_ack = True
        self._emit(CODE_CONFIGURE_ACK, packet.identifier, packet.data)

    def _handle_nak(self, packet: Packet) -> None:
        for option_type, value in decode_options(packet.data).items():
            self.apply_nak(option_type, value)
        self.send_configure_request()

    def _handle_reject(self, packet: Packet) -> None:
        for option_type in decode_options(packet.data):
            logger.debug("%s peer rejected option %d", self.name, option_type)
            self._rejected.add(option_type)
        self.send_configure_request()

    def review_peer_option(self, option_type: int, value: bytes):
        """Return ("accept"|"reject"|"nak", replacement_value)."""
        return "accept", b""

    def apply_nak(self, option_type: int, value: bytes) -> None:
        self.options[option_type] = value

    def send_terminate_request(self) -> None:
        self._emit(CODE_TERMINATE_REQUEST, self._next_identifier(), b"")
