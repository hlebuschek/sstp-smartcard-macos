"""SSTP packet encoding (MS-SSTP).

Packet header, 4 bytes:

     0        1        2        3
    +--------+--------+--------+--------+
    |Version |Reserv C|      Length     |
    +--------+--------+--------+--------+

Version is 0x10 (major 1, minor 0). The C bit (least significant bit of the
second byte) marks a control packet. Length is 12 bits and counts the header.

Control packets carry a message type, an attribute count, and the attributes:

     0        1        2        3
    +--------+--------+--------+--------+
    |   Message Type  |  Num Attributes |
    +--------+--------+--------+--------+
    | Attribute ...                     |

Each attribute is a reserved byte, an ID byte, a 12-bit length that includes
the attribute's own 4-byte header, and the value.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

SSTP_VERSION = 0x10
HEADER_LEN = 4
MAX_PACKET_LEN = 0x0FFF

# The HTTP layer that carries every SSTP session.
SSTP_URI = "/sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/"

# Message types
MSG_CALL_CONNECT_REQUEST = 0x0001
MSG_CALL_CONNECT_ACK = 0x0002
MSG_CALL_CONNECT_NAK = 0x0003
MSG_CALL_CONNECTED = 0x0004
MSG_CALL_ABORT = 0x0005
MSG_CALL_DISCONNECT = 0x0006
MSG_CALL_DISCONNECT_ACK = 0x0007
MSG_ECHO_REQUEST = 0x0008
MSG_ECHO_RESPONSE = 0x0009

MESSAGE_NAMES = {
    MSG_CALL_CONNECT_REQUEST: "Call Connect Request",
    MSG_CALL_CONNECT_ACK: "Call Connect Ack",
    MSG_CALL_CONNECT_NAK: "Call Connect Nak",
    MSG_CALL_CONNECTED: "Call Connected",
    MSG_CALL_ABORT: "Call Abort",
    MSG_CALL_DISCONNECT: "Call Disconnect",
    MSG_CALL_DISCONNECT_ACK: "Call Disconnect Ack",
    MSG_ECHO_REQUEST: "Echo Request",
    MSG_ECHO_RESPONSE: "Echo Response",
}

# Attribute IDs
ATTR_NO_ERROR = 0x00
ATTR_ENCAPSULATED_PROTOCOL_ID = 0x01
ATTR_STATUS_INFO = 0x02
ATTR_CRYPTO_BINDING = 0x03
ATTR_CRYPTO_BINDING_REQ = 0x04

PROTOCOL_ID_PPP = 0x0001

# Certificate hash protocol bitmask
CERT_HASH_PROTOCOL_SHA1 = 0x01
CERT_HASH_PROTOCOL_SHA256 = 0x02

# Values for the Status Info attribute
ATTRIB_STATUS_NO_ERROR = 0x00000000
ATTRIB_STATUS_DUPLICATE_ATTRIBUTE = 0x00000001
ATTRIB_STATUS_UNRECOGNIZED_ATTRIBUTE = 0x00000002
ATTRIB_STATUS_INVALID_ATTRIB_VALUE_LENGTH = 0x00000003
ATTRIB_STATUS_VALUE_NOT_SUPPORTED = 0x00000004
ATTRIB_STATUS_UNACCEPTED_FRAME_RECEIVED = 0x00000005
ATTRIB_STATUS_RETRY_COUNT_EXCEEDED = 0x00000006
ATTRIB_STATUS_INVALID_FRAME_RECEIVED = 0x00000007
ATTRIB_STATUS_NEGOTIATION_TIMEOUT = 0x00000008
ATTRIB_STATUS_ATTRIB_NOT_SUPPORTED_IN_MSG = 0x00000009
ATTRIB_STATUS_REQUIRED_ATTRIBUTE_MISSING = 0x0000000A
ATTRIB_STATUS_STATUS_INFO_NOT_SUPPORTED_IN_MSG = 0x0000000B

STATUS_NAMES = {
    ATTRIB_STATUS_NO_ERROR: "no error",
    ATTRIB_STATUS_DUPLICATE_ATTRIBUTE: "duplicate attribute",
    ATTRIB_STATUS_UNRECOGNIZED_ATTRIBUTE: "unrecognized attribute",
    ATTRIB_STATUS_INVALID_ATTRIB_VALUE_LENGTH: "invalid attribute value length",
    ATTRIB_STATUS_VALUE_NOT_SUPPORTED: "attribute value not supported",
    ATTRIB_STATUS_UNACCEPTED_FRAME_RECEIVED: "unaccepted frame received",
    ATTRIB_STATUS_RETRY_COUNT_EXCEEDED: "retry count exceeded",
    ATTRIB_STATUS_INVALID_FRAME_RECEIVED: "invalid frame received",
    ATTRIB_STATUS_NEGOTIATION_TIMEOUT: "negotiation timeout",
    ATTRIB_STATUS_ATTRIB_NOT_SUPPORTED_IN_MSG: "attribute not supported in message",
    ATTRIB_STATUS_REQUIRED_ATTRIBUTE_MISSING: "required attribute missing",
    ATTRIB_STATUS_STATUS_INFO_NOT_SUPPORTED_IN_MSG: "status info not supported in message",
}


class ProtocolError(Exception):
    pass


@dataclass
class Attribute:
    attribute_id: int
    value: bytes

    def encode(self) -> bytes:
        length = len(self.value) + 4
        if length > MAX_PACKET_LEN:
            raise ProtocolError(f"attribute too long: {length}")
        return struct.pack("!BBH", 0, self.attribute_id, length) + self.value


@dataclass
class ControlPacket:
    message_type: int
    attributes: list[Attribute] = field(default_factory=list)

    def encode(self) -> bytes:
        body = b"".join(attribute.encode() for attribute in self.attributes)
        payload = struct.pack("!HH", self.message_type, len(self.attributes)) + body
        return encode_packet(payload, control=True)

    def find(self, attribute_id: int) -> bytes | None:
        for attribute in self.attributes:
            if attribute.attribute_id == attribute_id:
                return attribute.value
        return None

    def __str__(self) -> str:
        name = MESSAGE_NAMES.get(self.message_type, f"0x{self.message_type:04x}")
        ids = ", ".join(f"0x{a.attribute_id:02x}" for a in self.attributes)
        return f"{name} [{ids}]" if ids else name


def encode_packet(payload: bytes, control: bool) -> bytes:
    length = len(payload) + HEADER_LEN
    if length > MAX_PACKET_LEN:
        raise ProtocolError(f"packet too long: {length}")
    return struct.pack("!BBH", SSTP_VERSION, 0x01 if control else 0x00, length) + payload


def encode_data_packet(ppp_frame: bytes) -> bytes:
    return encode_packet(ppp_frame, control=False)


def parse_header(data: bytes) -> tuple[bool, int]:
    """Return (is_control, total_length) for a 4-byte header."""
    if len(data) < HEADER_LEN:
        raise ProtocolError("short header")
    version, flags, length = struct.unpack("!BBH", data[:HEADER_LEN])
    if version != SSTP_VERSION:
        raise ProtocolError(f"unsupported SSTP version 0x{version:02x}")
    length &= MAX_PACKET_LEN
    if length < HEADER_LEN:
        raise ProtocolError(f"invalid packet length {length}")
    return bool(flags & 0x01), length


def parse_control(payload: bytes) -> ControlPacket:
    """Parse a control packet body (everything after the 4-byte header)."""
    if len(payload) < 4:
        raise ProtocolError("short control packet")
    message_type, count = struct.unpack("!HH", payload[:4])
    attributes = []
    offset = 4
    for _ in range(count):
        if offset + 4 > len(payload):
            raise ProtocolError("truncated attribute header")
        _, attribute_id, length = struct.unpack("!BBH", payload[offset : offset + 4])
        length &= MAX_PACKET_LEN
        if length < 4 or offset + length > len(payload):
            raise ProtocolError(f"invalid attribute length {length}")
        attributes.append(
            Attribute(attribute_id, payload[offset + 4 : offset + length])
        )
        offset += length
    return ControlPacket(message_type, attributes)


def status_text(value: bytes) -> str:
    """Render a Status Info attribute for logging."""
    if len(value) < 8:
        return f"malformed status info ({value.hex()})"
    attribute_id = value[3]
    (status,) = struct.unpack("!I", value[4:8])
    name = STATUS_NAMES.get(status, f"status 0x{status:08x}")
    return f"attribute 0x{attribute_id:02x}: {name}"
