"""EAP over PPP, carrying an EAP-TLS conversation (RFC 3748, RFC 5216)."""

from __future__ import annotations

import struct

from .. import log
from ..tls import TlsClient
from . import frame

logger = log.get("eap")

CODE_REQUEST = 1
CODE_RESPONSE = 2
CODE_SUCCESS = 3
CODE_FAILURE = 4

TYPE_IDENTITY = 1
TYPE_NOTIFICATION = 2
TYPE_NAK = 3
TYPE_MD5_CHALLENGE = 4
TYPE_TLS = 13

FLAG_LENGTH_INCLUDED = 0x80
FLAG_MORE_FRAGMENTS = 0x40
FLAG_START = 0x20

# Keeps each EAP response inside a typical 1400-byte PPP MRU.
FRAGMENT_SIZE = 1024


class EapError(Exception):
    pass


class EapAuthenticator:
    def __init__(self, identity, token, username: str, send, **tls_options):
        self.identity = identity
        self.token = token
        self.username = username
        self.send = send
        self.tls_options = tls_options

        self.tls: TlsClient | None = None
        self.succeeded = False
        self.failed = False
        self.msk = b""

        self._outgoing = b""
        self._outgoing_offset = 0
        self._incoming = bytearray()

    def handle(self, payload: bytes) -> None:
        if len(payload) < 4:
            raise EapError("short EAP packet")
        code, identifier, length = struct.unpack("!BBH", payload[:4])
        body = payload[4 : max(length, 4)]

        if code == CODE_SUCCESS:
            self._on_success()
            return
        if code == CODE_FAILURE:
            self.failed = True
            logger.error("server rejected authentication (EAP-Failure)")
            return
        if code != CODE_REQUEST:
            logger.debug("ignoring EAP code %d", code)
            return
        if not body:
            raise EapError("EAP request without a type")

        request_type = body[0]
        if request_type == TYPE_IDENTITY:
            self._send(CODE_RESPONSE, identifier, TYPE_IDENTITY, self.username.encode())
            logger.info("sent EAP identity %r", self.username)
        elif request_type == TYPE_TLS:
            self._handle_tls(identifier, body[1:])
        elif request_type == TYPE_NOTIFICATION:
            self._send(CODE_RESPONSE, identifier, TYPE_NOTIFICATION, b"")
        else:
            # Tell the server we only speak EAP-TLS.
            logger.info("server offered EAP type %d, requesting EAP-TLS", request_type)
            self._send(CODE_RESPONSE, identifier, TYPE_NAK, bytes([TYPE_TLS]))

    def _handle_tls(self, identifier: int, body: bytes) -> None:
        if not body:
            raise EapError("EAP-TLS request without flags")
        flags = body[0]
        offset = 1
        if flags & FLAG_LENGTH_INCLUDED:
            if len(body) < 5:
                raise EapError("EAP-TLS length flag set but no length present")
            offset = 5
        data = body[offset:]

        if flags & FLAG_START:
            logger.info("EAP-TLS start")
            self.tls = TlsClient(self.identity, self.token, **self.tls_options)
            self._outgoing = self.tls.start()
            self._outgoing_offset = 0
            self._send_fragment(identifier)
            return

        if self.tls is None:
            raise EapError("EAP-TLS data before start")

        # An empty request acknowledges our fragment; send the next one.
        if not data and self._has_pending_fragments():
            self._send_fragment(identifier)
            return

        self._incoming += data
        if flags & FLAG_MORE_FRAGMENTS:
            self._send(CODE_RESPONSE, identifier, TYPE_TLS, b"\x00")
            return

        chunk = bytes(self._incoming)
        self._incoming.clear()
        self._outgoing = self.tls.feed(chunk)
        self._outgoing_offset = 0

        if self._outgoing:
            self._send_fragment(identifier)
        else:
            # Handshake finished; an empty response tells the server to proceed.
            self._send(CODE_RESPONSE, identifier, TYPE_TLS, b"\x00")

    def _has_pending_fragments(self) -> bool:
        return self._outgoing_offset < len(self._outgoing)

    def _send_fragment(self, identifier: int) -> None:
        remaining = len(self._outgoing) - self._outgoing_offset
        first = self._outgoing_offset == 0
        chunk = self._outgoing[
            self._outgoing_offset : self._outgoing_offset + FRAGMENT_SIZE
        ]
        self._outgoing_offset += len(chunk)
        more = self._outgoing_offset < len(self._outgoing)

        flags = 0
        header = b""
        if more:
            flags |= FLAG_MORE_FRAGMENTS
        if first and (more or remaining > FRAGMENT_SIZE):
            flags |= FLAG_LENGTH_INCLUDED
            header = struct.pack("!I", len(self._outgoing))
        self._send(CODE_RESPONSE, identifier, TYPE_TLS, bytes([flags]) + header + chunk)
        logger.debug(
            "sent EAP-TLS fragment (%d bytes, more=%s)", len(chunk), bool(more)
        )

    def _on_success(self) -> None:
        if self.tls is None or not self.tls.handshake_complete:
            raise EapError("server sent EAP-Success before the TLS handshake completed")
        self.msk = self.tls.export_msk()
        self.succeeded = True
        logger.info("EAP-TLS authentication succeeded")

    def _send(self, code: int, identifier: int, eap_type: int, data: bytes) -> None:
        body = bytes([eap_type]) + data
        packet = struct.pack("!BBH", code, identifier, len(body) + 4) + body
        self.send(frame.PPP_EAP, packet)
