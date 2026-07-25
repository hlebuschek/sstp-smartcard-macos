"""A minimal TLS 1.2 client driven by byte buffers rather than a socket.

EAP-TLS carries TLS records inside EAP packets, so the handshake cannot use the
standard library's ssl module. This client also needs something ssl would never
allow: the CertificateVerify signature is produced by a smart card, and the
master secret must be exported to derive the EAP MSK.
"""

from __future__ import annotations

import os
import struct
import time

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from .. import log, trust
from . import crypto

logger = log.get("tls")

TLS_1_2 = 0x0303

CONTENT_CHANGE_CIPHER_SPEC = 20
CONTENT_ALERT = 21
CONTENT_HANDSHAKE = 22
CONTENT_APPLICATION_DATA = 23

HS_CLIENT_HELLO = 1
HS_SERVER_HELLO = 2
HS_CERTIFICATE = 11
HS_SERVER_KEY_EXCHANGE = 12
HS_CERTIFICATE_REQUEST = 13
HS_SERVER_HELLO_DONE = 14
HS_CERTIFICATE_VERIFY = 15
HS_CLIENT_KEY_EXCHANGE = 16
HS_FINISHED = 20

EXT_SERVER_NAME = 0x0000
EXT_SUPPORTED_GROUPS = 0x000A
EXT_EC_POINT_FORMATS = 0x000B
EXT_SIGNATURE_ALGORITHMS = 0x000D
EXT_EXTENDED_MASTER_SECRET = 0x0017
EXT_RENEGOTIATION_INFO = 0xFF01

ALERT_DESCRIPTIONS = {
    0: "close notify",
    10: "unexpected message",
    20: "bad record MAC",
    40: "handshake failure",
    42: "bad certificate",
    43: "unsupported certificate",
    44: "certificate revoked",
    45: "certificate expired",
    46: "certificate unknown",
    47: "illegal parameter",
    48: "unknown CA",
    49: "access denied",
    50: "decode error",
    51: "decrypt error",
    70: "protocol version",
    71: "insufficient security",
    80: "internal error",
    90: "user canceled",
    112: "unrecognized name",
    116: "certificate required",
}


class TlsError(Exception):
    pass


class TlsAlert(TlsError):
    def __init__(self, level: int, description: int):
        self.level = level
        self.description = description
        text = ALERT_DESCRIPTIONS.get(description, f"alert {description}")
        super().__init__(f"server sent {'fatal' if level == 2 else 'warning'}: {text}")


def _vector(data: bytes, length_bytes: int) -> bytes:
    return len(data).to_bytes(length_bytes, "big") + data


class TlsClient:
    def __init__(
        self,
        identity,
        token,
        server_name: str | None = None,
        ca_file: str | None = None,
        verify: bool = True,
    ):
        self.identity = identity
        self.token = token
        self.server_name = server_name
        self.ca_file = ca_file
        self.verify = verify

        self.client_random = struct.pack("!I", int(time.time())) + os.urandom(28)
        self.server_random = b""
        self.suite: crypto.CipherSuite | None = None
        self.master_secret = b""
        self.handshake_complete = False
        self.closed = False

        self._transcript = bytearray()
        self._inbound = bytearray()
        self._handshake_buffer = bytearray()
        self._outbound = bytearray()

        self._key_exchange: crypto.KeyExchange | None = None
        self._server_public = b""
        self._keys: crypto.SessionKeys | None = None
        self._server_certificates: list[x509.Certificate] = []
        self._certificate_requested = False
        self._server_signature_algorithms: list[tuple[int, int]] = []
        self._extended_master_secret = False
        self._write_protection: crypto.RecordProtection | None = None
        self._read_protection: crypto.RecordProtection | None = None
        self._server_hello_done = False

    # ---------------------------------------------------------------- public

    def start(self) -> bytes:
        self._send_client_hello()
        return self._flush()

    def feed(self, data: bytes) -> bytes:
        self._inbound += data
        while True:
            record = self._take_record()
            if record is None:
                break
            self._handle_record(*record)
        return self._flush()

    def export_msk(self, length: int = 64) -> bytes:
        """EAP-TLS key material (RFC 5216)."""
        if not self.handshake_complete:
            raise TlsError("handshake is not complete")
        return crypto.prf(
            self.master_secret,
            b"client EAP encryption",
            self.client_random + self.server_random,
            length,
            self.suite.prf_hash,
        )

    @property
    def server_certificate(self) -> x509.Certificate | None:
        return self._server_certificates[0] if self._server_certificates else None

    # --------------------------------------------------------------- records

    def _flush(self) -> bytes:
        data = bytes(self._outbound)
        self._outbound.clear()
        return data

    def _emit(self, content_type: int, payload: bytes) -> None:
        if self._write_protection is not None:
            payload = self._write_protection.encrypt(content_type, TLS_1_2, payload)
        self._outbound += struct.pack("!BHH", content_type, TLS_1_2, len(payload))
        self._outbound += payload

    def _take_record(self):
        if len(self._inbound) < 5:
            return None
        content_type, version, length = struct.unpack("!BHH", self._inbound[:5])
        if len(self._inbound) < 5 + length:
            return None
        fragment = bytes(self._inbound[5 : 5 + length])
        del self._inbound[: 5 + length]
        if self._read_protection is not None and content_type != CONTENT_CHANGE_CIPHER_SPEC:
            try:
                fragment = self._read_protection.decrypt(content_type, version, fragment)
            except ValueError as exc:
                raise TlsError(f"cannot decrypt record: {exc}") from exc
        return content_type, fragment

    def _handle_record(self, content_type: int, fragment: bytes) -> None:
        if content_type == CONTENT_ALERT:
            if len(fragment) < 2:
                raise TlsError("malformed alert")
            level, description = fragment[0], fragment[1]
            if description == 0 and self.handshake_complete:
                logger.debug("server sent close notify")
                self.closed = True
                return
            raise TlsAlert(level, description)
        if content_type == CONTENT_CHANGE_CIPHER_SPEC:
            self._activate_read_protection()
            return
        if content_type != CONTENT_HANDSHAKE:
            logger.debug("ignoring record of type %d", content_type)
            return

        self._handshake_buffer += fragment
        while len(self._handshake_buffer) >= 4:
            message_type = self._handshake_buffer[0]
            length = int.from_bytes(self._handshake_buffer[1:4], "big")
            if len(self._handshake_buffer) < 4 + length:
                break
            message = bytes(self._handshake_buffer[: 4 + length])
            del self._handshake_buffer[: 4 + length]
            self._handle_handshake(message_type, message[4:], message)

    # ------------------------------------------------------------- handshake

    def _handle_handshake(self, message_type: int, body: bytes, raw: bytes) -> None:
        # The Finished verify_data covers everything before it, so the
        # transcript must be updated after verification for that message only.
        if message_type == HS_FINISHED:
            self._handle_finished(body)
            self._transcript += raw
            return

        self._transcript += raw
        if message_type == HS_SERVER_HELLO:
            self._handle_server_hello(body)
        elif message_type == HS_CERTIFICATE:
            self._handle_certificate(body)
        elif message_type == HS_SERVER_KEY_EXCHANGE:
            self._handle_server_key_exchange(body)
        elif message_type == HS_CERTIFICATE_REQUEST:
            self._handle_certificate_request(body)
        elif message_type == HS_SERVER_HELLO_DONE:
            self._server_hello_done = True
            self._send_client_flight()
        else:
            logger.debug("ignoring handshake message type %d", message_type)

    def _send_handshake(self, message_type: int, body: bytes) -> None:
        message = struct.pack("!B", message_type) + len(body).to_bytes(3, "big") + body
        self._transcript += message
        self._emit(CONTENT_HANDSHAKE, message)

    def _send_client_hello(self) -> None:
        suites = b"".join(struct.pack("!H", s.value) for s in crypto.CIPHER_SUITES)
        extensions = bytearray()

        if self.server_name:
            name = self.server_name.encode("idna")
            entry = struct.pack("!B", 0) + _vector(name, 2)
            extensions += struct.pack("!H", EXT_SERVER_NAME) + _vector(
                _vector(entry, 2), 2
            )

        groups = b"".join(struct.pack("!H", g) for g in crypto.SUPPORTED_GROUPS)
        extensions += struct.pack("!H", EXT_SUPPORTED_GROUPS) + _vector(
            _vector(groups, 2), 2
        )
        extensions += struct.pack("!H", EXT_EC_POINT_FORMATS) + _vector(
            _vector(b"\x00", 1), 2
        )
        algorithms = b"".join(
            bytes(pair) for pair in crypto.SIGNATURE_ALGORITHMS
        )
        extensions += struct.pack("!H", EXT_SIGNATURE_ALGORITHMS) + _vector(
            _vector(algorithms, 2), 2
        )
        extensions += struct.pack("!H", EXT_EXTENDED_MASTER_SECRET) + _vector(b"", 2)
        extensions += struct.pack("!H", EXT_RENEGOTIATION_INFO) + _vector(
            _vector(b"", 1), 2
        )

        body = (
            struct.pack("!H", TLS_1_2)
            + self.client_random
            + _vector(b"", 1)
            + _vector(suites, 2)
            + _vector(b"\x00", 1)
            + _vector(bytes(extensions), 2)
        )
        self._send_handshake(HS_CLIENT_HELLO, body)
        logger.debug("sent ClientHello with %d cipher suites", len(crypto.CIPHER_SUITES))

    def _handle_server_hello(self, body: bytes) -> None:
        if len(body) < 38:
            raise TlsError("short ServerHello")
        (version,) = struct.unpack("!H", body[:2])
        if version != TLS_1_2:
            raise TlsError(
                f"server selected TLS version 0x{version:04x}; only TLS 1.2 is supported"
            )
        self.server_random = body[2:34]
        offset = 34
        session_id_length = body[offset]
        offset += 1 + session_id_length
        (suite_value,) = struct.unpack("!H", body[offset : offset + 2])
        offset += 2
        offset += 1  # compression method

        suite = crypto.SUITES_BY_VALUE.get(suite_value)
        if suite is None:
            raise TlsError(f"server selected unsupported cipher suite 0x{suite_value:04x}")
        self.suite = suite
        logger.info("TLS 1.2 cipher suite: %s", suite.name)

        if offset + 2 <= len(body):
            (extensions_length,) = struct.unpack("!H", body[offset : offset + 2])
            offset += 2
            end = offset + extensions_length
            while offset + 4 <= end:
                ext_type, ext_length = struct.unpack("!HH", body[offset : offset + 4])
                if ext_type == EXT_EXTENDED_MASTER_SECRET:
                    self._extended_master_secret = True
                offset += 4 + ext_length
        logger.debug("extended master secret: %s", self._extended_master_secret)

    def _handle_certificate(self, body: bytes) -> None:
        if len(body) < 3:
            raise TlsError("short Certificate message")
        total = int.from_bytes(body[:3], "big")
        offset = 3
        end = 3 + total
        certificates = []
        while offset + 3 <= end:
            length = int.from_bytes(body[offset : offset + 3], "big")
            offset += 3
            der = body[offset : offset + length]
            offset += length
            try:
                certificates.append(x509.load_der_x509_certificate(der))
            except ValueError as exc:
                raise TlsError(f"cannot parse server certificate: {exc}") from exc
        if not certificates:
            raise TlsError("server sent an empty certificate chain")
        self._server_certificates = certificates
        logger.info(
            "server certificate: %s", certificates[0].subject.rfc4514_string()
        )
        self._verify_server_certificate()

    def _verify_server_certificate(self) -> None:
        certificate = self._server_certificates[0]
        now = time.time()
        if certificate.not_valid_after_utc.timestamp() < now:
            raise TlsError("server certificate has expired")
        if certificate.not_valid_before_utc.timestamp() > now:
            raise TlsError("server certificate is not yet valid")

        if not self.verify:
            logger.warning(
                "inner TLS: server certificate chain NOT verified (verification disabled)"
            )
            return
        from cryptography.x509 import verification

        if self.ca_file:
            with open(self.ca_file, "rb") as handle:
                anchors = x509.load_pem_x509_certificates(handle.read())
        else:
            # The EAP server's certificate is issued by the same enterprise CA
            # as the outer one, which lives in the keychain rather than in
            # Python's bundled roots.
            anchors = trust.system_certificates()
        if not anchors:
            raise TlsError(
                "no trust anchors available to verify the EAP-TLS server; "
                "pass --inner-ca-file"
            )
        store = verification.Store(anchors)
        builder = verification.PolicyBuilder().store(store)
        name = self.server_name or _first_dns_name(certificate)
        if name is None:
            raise TlsError("cannot determine a server name to verify against")
        verifier = builder.build_server_verifier(x509.DNSName(name))
        try:
            verifier.verify(certificate, self._server_certificates[1:])
        except Exception as exc:
            raise TlsError(
                f"EAP-TLS server certificate verification failed: {exc} "
                "(override with --inner-ca-file or --no-verify-inner)"
            ) from exc
        logger.info("inner TLS: server certificate chain verified")

    def _handle_server_key_exchange(self, body: bytes) -> None:
        if self.suite.key_exchange != "ecdhe":
            raise TlsError("unexpected ServerKeyExchange for a non-ECDHE suite")
        if len(body) < 4 or body[0] != 3:
            raise TlsError("only named curve ECDHE parameters are supported")
        (group,) = struct.unpack("!H", body[1:3])
        point_length = body[3]
        point = body[4 : 4 + point_length]
        params = body[: 4 + point_length]
        offset = 4 + point_length

        if offset + 4 > len(body):
            raise TlsError("ServerKeyExchange is missing its signature")
        hash_id, signature_id = body[offset], body[offset + 1]
        (signature_length,) = struct.unpack("!H", body[offset + 2 : offset + 4])
        signature = body[offset + 4 : offset + 4 + signature_length]

        hash_name = crypto.HASH_BY_ID.get(hash_id)
        if hash_name is None:
            raise TlsError(f"unsupported signature hash {hash_id}")
        signed = self.client_random + self.server_random + params
        self._verify_server_signature(signed, signature, hash_name, signature_id)

        if group not in crypto.SUPPORTED_GROUPS:
            raise TlsError(f"server chose unsupported group {group}")
        self._key_exchange = crypto.KeyExchange(group)
        self._server_public = point
        logger.debug("ECDHE group %d accepted", group)

    def _verify_server_signature(
        self, signed: bytes, signature: bytes, hash_name: str, signature_id: int
    ) -> None:
        public_key = self._server_certificates[0].public_key()
        algorithm = crypto.hash_algorithm(hash_name)
        try:
            if signature_id == 1 and isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(signature, signed, padding.PKCS1v15(), algorithm)
            elif signature_id == 3 and isinstance(
                public_key, ec.EllipticCurvePublicKey
            ):
                public_key.verify(signature, signed, ec.ECDSA(algorithm))
            else:
                raise TlsError(
                    f"signature algorithm {signature_id} does not match the server key"
                )
        except InvalidSignature as exc:
            raise TlsError("ServerKeyExchange signature is invalid") from exc
        logger.debug("ServerKeyExchange signature verified")

    def _handle_certificate_request(self, body: bytes) -> None:
        self._certificate_requested = True
        if len(body) < 1:
            return
        offset = 1 + body[0]
        if offset + 2 <= len(body):
            (length,) = struct.unpack("!H", body[offset : offset + 2])
            offset += 2
            pairs = body[offset : offset + length]
            self._server_signature_algorithms = [
                (pairs[i], pairs[i + 1]) for i in range(0, len(pairs) - 1, 2)
            ]
        logger.debug(
            "server requested a client certificate (%d signature algorithms)",
            len(self._server_signature_algorithms),
        )

    # ---------------------------------------------------------- client flight

    def _send_client_flight(self) -> None:
        if self._certificate_requested:
            self._send_client_certificate()

        premaster = self._send_client_key_exchange()
        self._derive_master_secret(premaster)

        if self._certificate_requested:
            self._send_certificate_verify()

        self._emit(CONTENT_CHANGE_CIPHER_SPEC, b"\x01")
        self._activate_write_protection()
        verify_data = crypto.prf(
            self.master_secret,
            b"client finished",
            crypto.handshake_hash(bytes(self._transcript), self.suite.prf_hash),
            12,
            self.suite.prf_hash,
        )
        self._send_handshake(HS_FINISHED, verify_data)
        logger.debug("client flight sent")

    def _send_client_certificate(self) -> None:
        entry = _vector(self.identity.cert_der, 3)
        self._send_handshake(HS_CERTIFICATE, _vector(entry, 3))
        logger.info("sent client certificate from the token")

    def _send_client_key_exchange(self) -> bytes:
        if self.suite.key_exchange == "ecdhe":
            public = self._key_exchange.public_bytes()
            self._send_handshake(HS_CLIENT_KEY_EXCHANGE, _vector(public, 1))
            return self._key_exchange.exchange(self._server_public)

        premaster = struct.pack("!H", TLS_1_2) + os.urandom(46)
        public_key = self._server_certificates[0].public_key()
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise TlsError("RSA key exchange requires an RSA server certificate")
        encrypted = public_key.encrypt(premaster, padding.PKCS1v15())
        self._send_handshake(HS_CLIENT_KEY_EXCHANGE, _vector(encrypted, 2))
        return premaster

    def _derive_master_secret(self, premaster: bytes) -> None:
        if self._extended_master_secret:
            session_hash = crypto.handshake_hash(
                bytes(self._transcript), self.suite.prf_hash
            )
            self.master_secret = crypto.prf(
                premaster, b"extended master secret", session_hash, 48, self.suite.prf_hash
            )
        else:
            self.master_secret = crypto.prf(
                premaster,
                b"master secret",
                self.client_random + self.server_random,
                48,
                self.suite.prf_hash,
            )
        self._keys = crypto.derive_keys(
            self.master_secret, self.client_random, self.server_random, self.suite
        )

    def _send_certificate_verify(self) -> None:
        hash_name, signature_id = self._choose_signature_algorithm()
        digest = crypto.handshake_hash(bytes(self._transcript), hash_name)
        logger.info("signing CertificateVerify on the token (%s)", hash_name)
        signature = self.token.sign(self.identity, digest, hash_name)
        hash_id = next(k for k, v in crypto.HASH_BY_ID.items() if v == hash_name)
        body = bytes([hash_id, signature_id]) + _vector(signature, 2)
        self._send_handshake(HS_CERTIFICATE_VERIFY, body)

    def _choose_signature_algorithm(self) -> tuple[str, int]:
        signature_id = 1 if self.identity.key_type == "rsa" else 3
        preferred = ["sha256", "sha384", "sha512", "sha1"]
        offered = [
            crypto.HASH_BY_ID.get(hash_id)
            for hash_id, sig_id in self._server_signature_algorithms
            if sig_id == signature_id
        ]
        for name in preferred:
            if name in offered:
                return name, signature_id
        if not offered:
            return "sha256", signature_id
        raise TlsError("no mutually supported signature algorithm for the card key")

    def _activate_write_protection(self) -> None:
        self._write_protection = crypto.RecordProtection(
            self.suite,
            self._keys.client_key,
            self._keys.client_mac,
            self._keys.client_iv,
        )

    def _activate_read_protection(self) -> None:
        self._read_protection = crypto.RecordProtection(
            self.suite,
            self._keys.server_key,
            self._keys.server_mac,
            self._keys.server_iv,
        )

    def _handle_finished(self, body: bytes) -> None:
        expected = crypto.prf(
            self.master_secret,
            b"server finished",
            crypto.handshake_hash(bytes(self._transcript), self.suite.prf_hash),
            12,
            self.suite.prf_hash,
        )
        if body != expected:
            raise TlsError("server Finished verify_data mismatch")
        self.handshake_complete = True
        logger.info("inner TLS handshake complete")


def _first_dns_name(certificate: x509.Certificate) -> str | None:
    try:
        san = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except x509.ExtensionNotFound:
        return None
    names = san.get_values_for_type(x509.DNSName)
    return names[0] if names else None
