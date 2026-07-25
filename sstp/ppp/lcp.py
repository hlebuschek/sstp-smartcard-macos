"""LCP negotiation."""

from __future__ import annotations

import os
import struct

from .. import log
from . import frame
from .frame import ConfigureFsm, Packet

logger = log.get("lcp")

OPTION_MRU = 1
OPTION_ACCM = 2
OPTION_AUTH_PROTOCOL = 3
OPTION_QUALITY_PROTOCOL = 4
OPTION_MAGIC_NUMBER = 5
OPTION_PROTOCOL_COMPRESSION = 7
OPTION_ADDRESS_CONTROL_COMPRESSION = 8

DEFAULT_MRU = 1400


class Lcp(ConfigureFsm):
    def __init__(self, send, mru: int = DEFAULT_MRU):
        super().__init__(frame.PPP_LCP, "lcp", send)
        self.magic = os.urandom(4)
        self.options = {
            OPTION_MRU: struct.pack("!H", mru),
            OPTION_MAGIC_NUMBER: self.magic,
        }
        self.auth_protocol: int | None = None
        self.peer_magic = b"\x00\x00\x00\x00"
        self.terminated = False

    def review_peer_option(self, option_type: int, value: bytes):
        if option_type == OPTION_AUTH_PROTOCOL:
            if len(value) >= 2:
                (proposed,) = struct.unpack("!H", value[:2])
                if proposed == frame.PPP_EAP:
                    self.auth_protocol = proposed
                    return "accept", b""
                # Only EAP carries a smart card certificate, so steer the
                # server away from password-based methods.
                logger.info(
                    "server proposed auth protocol 0x%04x, requesting EAP instead",
                    proposed,
                )
                return "nak", struct.pack("!H", frame.PPP_EAP)
            return "reject", b""

        if option_type == OPTION_MAGIC_NUMBER:
            self.peer_magic = value
            return "accept", b""

        if option_type in (OPTION_MRU, OPTION_ACCM):
            return "accept", b""

        # Without HDLC framing these compressions only complicate parsing.
        if option_type in (
            OPTION_PROTOCOL_COMPRESSION,
            OPTION_ADDRESS_CONTROL_COMPRESSION,
        ):
            return "reject", b""

        logger.debug("rejecting unsupported LCP option %d", option_type)
        return "reject", b""

    def handle(self, payload: bytes) -> Packet:
        packet = super().handle(payload)

        if packet.code == frame.CODE_ECHO_REQUEST:
            self._emit(
                frame.CODE_ECHO_REPLY, packet.identifier, self.magic + packet.data[4:]
            )
        elif packet.code == frame.CODE_TERMINATE_REQUEST:
            self._emit(frame.CODE_TERMINATE_ACK, packet.identifier, b"")
            self.terminated = True
            logger.warning("server terminated the PPP link")
        elif packet.code == frame.CODE_PROTOCOL_REJECT and len(packet.data) >= 2:
            (rejected,) = struct.unpack("!H", packet.data[:2])
            logger.warning("server rejected PPP protocol 0x%04x", rejected)
        return packet

    def send_echo_request(self) -> None:
        self._emit(frame.CODE_ECHO_REQUEST, self._next_identifier(), self.magic)
