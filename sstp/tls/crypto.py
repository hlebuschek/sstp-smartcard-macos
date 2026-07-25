"""TLS 1.2 key schedule, cipher suites and record protection.

Only what EAP-TLS needs: a client-side TLS 1.2 handshake with ECDHE or RSA key
exchange, AES in GCM or CBC mode.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Named groups
GROUP_SECP256R1 = 23
GROUP_SECP384R1 = 24
GROUP_X25519 = 29

SUPPORTED_GROUPS = (GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1)

# Signature/hash algorithm pairs for the signature_algorithms extension
SIGNATURE_ALGORITHMS = (
    (0x04, 0x01),  # sha256, rsa
    (0x05, 0x01),  # sha384, rsa
    (0x06, 0x01),  # sha512, rsa
    (0x04, 0x03),  # sha256, ecdsa
    (0x05, 0x03),  # sha384, ecdsa
    (0x02, 0x01),  # sha1, rsa
)

HASH_BY_ID = {0x02: "sha1", 0x04: "sha256", 0x05: "sha384", 0x06: "sha512"}
HASH_MODULES = {
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
}


@dataclass(frozen=True)
class CipherSuite:
    value: int
    name: str
    key_exchange: str  # "ecdhe" or "rsa"
    authentication: str  # "rsa", "ecdsa" or "" for plain RSA key exchange
    cipher: str  # "aes-gcm" or "aes-cbc"
    key_length: int
    mac: str  # "" for AEAD suites
    prf_hash: str


# Ordered by preference.
CIPHER_SUITES = (
    CipherSuite(0xC02F, "ECDHE_RSA_AES_128_GCM_SHA256", "ecdhe", "rsa", "aes-gcm", 16, "", "sha256"),
    CipherSuite(0xC030, "ECDHE_RSA_AES_256_GCM_SHA384", "ecdhe", "rsa", "aes-gcm", 32, "", "sha384"),
    CipherSuite(0xC02B, "ECDHE_ECDSA_AES_128_GCM_SHA256", "ecdhe", "ecdsa", "aes-gcm", 16, "", "sha256"),
    CipherSuite(0xC02C, "ECDHE_ECDSA_AES_256_GCM_SHA384", "ecdhe", "ecdsa", "aes-gcm", 32, "", "sha384"),
    CipherSuite(0xC027, "ECDHE_RSA_AES_128_CBC_SHA256", "ecdhe", "rsa", "aes-cbc", 16, "sha256", "sha256"),
    CipherSuite(0xC028, "ECDHE_RSA_AES_256_CBC_SHA384", "ecdhe", "rsa", "aes-cbc", 32, "sha384", "sha384"),
    CipherSuite(0xC013, "ECDHE_RSA_AES_128_CBC_SHA", "ecdhe", "rsa", "aes-cbc", 16, "sha1", "sha256"),
    CipherSuite(0xC014, "ECDHE_RSA_AES_256_CBC_SHA", "ecdhe", "rsa", "aes-cbc", 32, "sha1", "sha256"),
    CipherSuite(0x009C, "RSA_AES_128_GCM_SHA256", "rsa", "", "aes-gcm", 16, "", "sha256"),
    CipherSuite(0x009D, "RSA_AES_256_GCM_SHA384", "rsa", "", "aes-gcm", 32, "", "sha384"),
    CipherSuite(0x003C, "RSA_AES_128_CBC_SHA256", "rsa", "", "aes-cbc", 16, "sha256", "sha256"),
    CipherSuite(0x002F, "RSA_AES_128_CBC_SHA", "rsa", "", "aes-cbc", 16, "sha1", "sha256"),
    CipherSuite(0x0035, "RSA_AES_256_CBC_SHA", "rsa", "", "aes-cbc", 32, "sha1", "sha256"),
)

SUITES_BY_VALUE = {suite.value: suite for suite in CIPHER_SUITES}

MAC_LENGTHS = {"": 0, "sha1": 20, "sha256": 32, "sha384": 48}


def p_hash(secret: bytes, seed: bytes, length: int, hash_name: str) -> bytes:
    module = HASH_MODULES[hash_name]
    output = b""
    a = seed
    while len(output) < length:
        a = hmac.new(secret, a, module).digest()
        output += hmac.new(secret, a + seed, module).digest()
    return output[:length]


def prf(secret: bytes, label: bytes, seed: bytes, length: int, hash_name: str) -> bytes:
    return p_hash(secret, label + seed, length, hash_name)


def handshake_hash(messages: bytes, hash_name: str) -> bytes:
    return HASH_MODULES[hash_name](messages).digest()


class KeyExchange:
    """Ephemeral key agreement for the negotiated named group."""

    def __init__(self, group: int):
        if group not in SUPPORTED_GROUPS:
            raise ValueError(f"unsupported group {group}")
        self.group = group
        if group == GROUP_X25519:
            self._private = x25519.X25519PrivateKey.generate()
        else:
            curve = ec.SECP256R1() if group == GROUP_SECP256R1 else ec.SECP384R1()
            self._private = ec.generate_private_key(curve)

    def public_bytes(self) -> bytes:
        if self.group == GROUP_X25519:
            from cryptography.hazmat.primitives.serialization import (
                Encoding,
                PublicFormat,
            )

            return self._private.public_key().public_bytes(
                Encoding.Raw, PublicFormat.Raw
            )
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        return self._private.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        )

    def exchange(self, peer_public: bytes) -> bytes:
        if self.group == GROUP_X25519:
            peer = x25519.X25519PublicKey.from_public_bytes(peer_public)
            return self._private.exchange(peer)
        curve = ec.SECP256R1() if self.group == GROUP_SECP256R1 else ec.SECP384R1()
        peer = ec.EllipticCurvePublicKey.from_encoded_point(curve, peer_public)
        return self._private.exchange(ec.ECDH(), peer)


@dataclass
class SessionKeys:
    client_key: bytes
    server_key: bytes
    client_mac: bytes
    server_mac: bytes
    client_iv: bytes
    server_iv: bytes


def derive_keys(
    master_secret: bytes, client_random: bytes, server_random: bytes, suite: CipherSuite
) -> SessionKeys:
    mac_length = MAC_LENGTHS[suite.mac]
    # GCM uses a 4-byte salt as the fixed part of the nonce; CBC in TLS 1.2
    # carries an explicit IV in every record, so no fixed IV is derived.
    iv_length = 4 if suite.cipher == "aes-gcm" else 0
    needed = 2 * mac_length + 2 * suite.key_length + 2 * iv_length
    block = prf(
        master_secret,
        b"key expansion",
        server_random + client_random,
        needed,
        suite.prf_hash,
    )
    offset = 0

    def take(count: int) -> bytes:
        nonlocal offset
        value = block[offset : offset + count]
        offset += count
        return value

    client_mac = take(mac_length)
    server_mac = take(mac_length)
    client_key = take(suite.key_length)
    server_key = take(suite.key_length)
    client_iv = take(iv_length)
    server_iv = take(iv_length)
    return SessionKeys(
        client_key, server_key, client_mac, server_mac, client_iv, server_iv
    )


class RecordProtection:
    """Encrypts and decrypts TLS records for one direction."""

    def __init__(self, suite: CipherSuite, key: bytes, mac_key: bytes, iv: bytes):
        self.suite = suite
        self.key = key
        self.mac_key = mac_key
        self.iv = iv
        self.sequence = 0

    def _additional_data(self, content_type: int, version: int, length: int) -> bytes:
        return struct.pack("!QBHH", self.sequence, content_type, version, length)

    def encrypt(self, content_type: int, version: int, plaintext: bytes) -> bytes:
        if self.suite.cipher == "aes-gcm":
            explicit_nonce = struct.pack("!Q", self.sequence)
            aad = self._additional_data(content_type, version, len(plaintext))
            ciphertext = AESGCM(self.key).encrypt(
                self.iv + explicit_nonce, plaintext, aad
            )
            output = explicit_nonce + ciphertext
        else:
            module = HASH_MODULES[self.suite.mac]
            aad = self._additional_data(content_type, version, len(plaintext))
            mac = hmac.new(self.mac_key, aad + plaintext, module).digest()
            body = plaintext + mac
            pad_length = 16 - (len(body) + 1) % 16
            body += bytes([pad_length]) * (pad_length + 1)
            explicit_iv = _random_iv()
            encryptor = Cipher(
                algorithms.AES(self.key), modes.CBC(explicit_iv)
            ).encryptor()
            output = explicit_iv + encryptor.update(body) + encryptor.finalize()
        self.sequence += 1
        return output

    def decrypt(self, content_type: int, version: int, ciphertext: bytes) -> bytes:
        if self.suite.cipher == "aes-gcm":
            if len(ciphertext) < 8:
                raise ValueError("short GCM record")
            explicit_nonce, body = ciphertext[:8], ciphertext[8:]
            aad = self._additional_data(content_type, version, len(body) - 16)
            plaintext = AESGCM(self.key).decrypt(self.iv + explicit_nonce, body, aad)
        else:
            if len(ciphertext) < 32 or len(ciphertext) % 16:
                raise ValueError("malformed CBC record")
            explicit_iv, body = ciphertext[:16], ciphertext[16:]
            decryptor = Cipher(
                algorithms.AES(self.key), modes.CBC(explicit_iv)
            ).decryptor()
            padded = decryptor.update(body) + decryptor.finalize()
            pad_length = padded[-1]
            if pad_length + 1 > len(padded):
                raise ValueError("bad CBC padding")
            body = padded[: -(pad_length + 1)]
            mac_length = MAC_LENGTHS[self.suite.mac]
            plaintext, mac = body[:-mac_length], body[-mac_length:]
            module = HASH_MODULES[self.suite.mac]
            aad = self._additional_data(content_type, version, len(plaintext))
            expected = hmac.new(self.mac_key, aad + plaintext, module).digest()
            if not hmac.compare_digest(mac, expected):
                raise ValueError("record MAC mismatch")
        self.sequence += 1
        return plaintext


def _random_iv() -> bytes:
    import os

    return os.urandom(16)


def hash_algorithm(name: str):
    return {
        "sha1": hashes.SHA1(),
        "sha256": hashes.SHA256(),
        "sha384": hashes.SHA384(),
        "sha512": hashes.SHA512(),
    }[name]
