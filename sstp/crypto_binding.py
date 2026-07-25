"""SSTP cryptographic binding (MS-SSTP 3.2.5.2).

The binding proves that the endpoint which completed the inner PPP
authentication is the same one that owns the outer TLS channel: the client
signs the Call Connected message with a key derived from the inner method's
key material, and includes a hash of the server's TLS certificate.

Field layout and derivation verified against the accel-ppp SSTP server
implementation (accel-pppd/ctrl/sstp/sstp.c), which interoperates with the
Windows client:

    CMK = HMAC(HLAK, "SSTP inner method derived CMK" || len || 0x00 || 0x01)

where `len` is the digest length in bytes (32 for SHA-256, 20 for SHA-1) and
the seed string carries no terminating NUL. The Compound MAC is then

    HMAC(CMK, <entire Call Connected packet, Compound MAC field zeroed>)
"""

from __future__ import annotations

import hashlib
import hmac
import struct

from . import protocol

CMK_SEED = b"SSTP inner method derived CMK"
NONCE_LEN = 32
HLAK_LEN = 32

# Offsets within the encoded Call Connected packet:
#   0   SSTP header (4)
#   4   message type + attribute count (4)
#   8   attribute header (4)
#   12  reserved (3) + hash protocol bitmask (1)
#   16  nonce (32)
#   48  cert hash (32)
#   80  compound MAC (32)
#   112 end
CALL_CONNECTED_LEN = 112
_COMPOUND_MAC_OFFSET = 80


class BindingError(Exception):
    pass


def _digest(hash_protocol: int):
    if hash_protocol & protocol.CERT_HASH_PROTOCOL_SHA256:
        return hashlib.sha256, 32, protocol.CERT_HASH_PROTOCOL_SHA256
    if hash_protocol & protocol.CERT_HASH_PROTOCOL_SHA1:
        return hashlib.sha1, 20, protocol.CERT_HASH_PROTOCOL_SHA1
    raise BindingError(f"no supported hash protocol in bitmask 0x{hash_protocol:02x}")


def parse_binding_request(value: bytes) -> tuple[int, bytes]:
    """Parse a Crypto Binding Request attribute value into (bitmask, nonce)."""
    if len(value) < 4 + NONCE_LEN:
        raise BindingError(f"crypto binding request too short: {len(value)} bytes")
    bitmask = value[3]
    nonce = value[4 : 4 + NONCE_LEN]
    return bitmask, nonce


def certificate_hash(cert_der: bytes, hash_protocol: int) -> bytes:
    """Hash of the server's TLS certificate, padded to the 32-byte field."""
    algorithm, length, _ = _digest(hash_protocol)
    return algorithm(cert_der).digest().ljust(32, b"\x00")[:32]


def derive_cmk(hlak: bytes, hash_protocol: int) -> bytes:
    if len(hlak) != HLAK_LEN:
        raise BindingError(f"HLAK must be {HLAK_LEN} bytes, got {len(hlak)}")
    algorithm, length, _ = _digest(hash_protocol)
    seed = CMK_SEED + bytes([length, 0x00, 0x01])
    return hmac.new(hlak, seed, algorithm).digest()


def build_call_connected(
    hlak: bytes, nonce: bytes, cert_der: bytes, hash_protocol: int
) -> bytes:
    """Build the complete Call Connected packet including its Compound MAC."""
    algorithm, _, selected = _digest(hash_protocol)
    if len(nonce) != NONCE_LEN:
        raise BindingError(f"nonce must be {NONCE_LEN} bytes, got {len(nonce)}")

    value = (
        b"\x00\x00\x00"
        + bytes([selected])
        + nonce
        + certificate_hash(cert_der, hash_protocol)
        + b"\x00" * 32  # Compound MAC, filled in below
    )
    packet = protocol.ControlPacket(
        protocol.MSG_CALL_CONNECTED,
        [protocol.Attribute(protocol.ATTR_CRYPTO_BINDING, value)],
    ).encode()

    if len(packet) != CALL_CONNECTED_LEN:
        raise BindingError(
            f"unexpected Call Connected length {len(packet)}, "
            f"expected {CALL_CONNECTED_LEN}"
        )

    cmk = derive_cmk(hlak, hash_protocol)
    mac = hmac.new(cmk, packet, algorithm).digest().ljust(32, b"\x00")[:32]
    return packet[:_COMPOUND_MAC_OFFSET] + mac + packet[_COMPOUND_MAC_OFFSET + 32 :]


def hlak_from_msk(msk: bytes) -> bytes:
    """HLAK for an EAP inner method.

    MS-SSTP takes the first 32 bytes of the EAP MSK. For EAP-TLS the MSK comes
    from the TLS PRF with the label "client EAP encryption" (RFC 5216).
    """
    if len(msk) < HLAK_LEN:
        raise BindingError(f"MSK too short: {len(msk)} bytes")
    return msk[:HLAK_LEN]


def hlak_from_mppe(send_key: bytes, recv_key: bytes) -> bytes:
    """HLAK for MS-CHAPv2: the 16-byte MPPE receive key followed by the send key."""
    return recv_key[:16] + send_key[:16]
