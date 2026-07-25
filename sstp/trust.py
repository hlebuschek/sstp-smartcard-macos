"""macOS trust anchors.

Python's ssl module ships its own CA bundle and ignores the system keychain, so
certificates issued by an enterprise CA deployed through MDM fail to verify.
This module exports those anchors so they can be handed to an SSLContext.
"""

from __future__ import annotations

import subprocess
import warnings

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.utils import CryptographyDeprecationWarning

from . import log

logger = log.get("trust")

KEYCHAINS = (
    "/System/Library/Keychains/SystemRootCertificates.keychain",
    "/Library/Keychains/System.keychain",
)

_BEGIN = "-----BEGIN CERTIFICATE-----"
_END = "-----END CERTIFICATE-----"


def _export(keychain: str) -> str:
    result = subprocess.run(
        ["security", "find-certificate", "-a", "-p", keychain],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        logger.debug("cannot read %s: %s", keychain, result.stderr.strip())
        return ""
    return result.stdout


def _parse(block: str):
    # Some shipped anchors predate RFC 5280 and warn on every parse; the
    # keychain's contents are not ours to fix, so the noise is not actionable.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", CryptographyDeprecationWarning)
        try:
            return x509.load_pem_x509_certificate(block.encode())
        except ValueError:
            return None


def system_certificates() -> list[x509.Certificate]:
    """Return the system's CA certificates.

    Malformed entries are skipped: a single bad certificate would otherwise
    make the whole bundle unusable.
    """
    seen = set()
    anchors = []
    for keychain in KEYCHAINS:
        text = _export(keychain)
        while _BEGIN in text and _END in text:
            start = text.index(_BEGIN)
            end = text.index(_END) + len(_END)
            block = text[start:end]
            text = text[end:]
            certificate = _parse(block)
            if certificate is None:
                continue
            fingerprint = certificate.fingerprint(hashes.SHA256())
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            anchors.append(certificate)
    logger.debug("loaded %d trust anchors from the keychain", len(anchors))
    return anchors


def system_anchors() -> str:
    """Return the system's CA certificates as a PEM bundle."""
    blocks = [
        certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
        for certificate in system_certificates()
    ]
    return "".join(blocks)
