"""PKCS#11 access to a smart card: certificate discovery and on-card signing.

The private key never leaves the token; every signature during the EAP-TLS
handshake is produced by a C_Sign call against the card.
"""

from __future__ import annotations

import datetime
import os
import re
from dataclasses import dataclass

import PyKCS11
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from . import log

logger = log.get("token")

# Where vendor middleware installs its PKCS#11 module on macOS. Order matters:
# the vendor module for the card in use is preferred over the generic OpenSC one.
KNOWN_MODULES = (
    "/usr/local/lib/pkcs11/libeTPkcs11.dylib",
    "/usr/local/lib/pkcs11/libIDPrimePKCS11.dylib",
    "/usr/local/lib/pkcs11/libClassicClientPKCS11.dylib",
    # JaCarta Unified Client; JaCarta PKI cards answer only to this module.
    "/Library/Frameworks/jcPKCS11-2.framework/jcPKCS11-2",
    "/usr/local/lib/libjcPKCS11.dylib",
    "/usr/local/lib/librtpkcs11ecp.dylib",
    "/opt/homebrew/lib/pkcs11/opensc-pkcs11.so",
    "/usr/local/lib/pkcs11/opensc-pkcs11.so",
)

EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
EKU_SMARTCARD_LOGON = "1.3.6.1.4.1.311.20.2.2"

# DigestInfo prefixes (RFC 8017 A.2.4). The card is asked to do a raw PKCS#1
# v1.5 signature, so the DigestInfo structure is assembled here.
_DIGEST_INFO = {
    "sha1": bytes.fromhex("3021300906052b0e03021a05000414"),
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}


class TokenError(Exception):
    pass


def _as_bytes(value) -> bytes:
    """PyKCS11 returns byte attributes as int lists but string ones as str."""
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8", "surrogateescape")
    return bytes(value)


def _as_text(value) -> str:
    text = _as_bytes(value).decode("utf-8", "replace").rstrip("\x00").strip()
    # The SafeNet module escapes non-ASCII label characters as !XXXX UTF-16 units.
    return re.sub(r"!([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), text)


@dataclass
class TokenInfo:
    slot: int
    label: str
    serial: str
    pin_count_low: bool
    pin_final_try: bool
    pin_locked: bool


@dataclass
class CardCertificate:
    """A certificate stored on the token, readable without a PIN."""

    label: str
    ckaid: bytes
    cert_der: bytes
    certificate: x509.Certificate

    @property
    def subject(self) -> str:
        return self.certificate.subject.rfc4514_string()

    @property
    def issuer(self) -> str:
        return self.certificate.issuer.rfc4514_string()

    @property
    def is_expired(self) -> bool:
        now = datetime.datetime.now(datetime.timezone.utc)
        return not (
            self.certificate.not_valid_before_utc
            <= now
            <= self.certificate.not_valid_after_utc
        )

    @property
    def is_self_signed(self) -> bool:
        return self.certificate.issuer == self.certificate.subject

    @property
    def extended_key_usage(self) -> list[str] | None:
        """The EKU OIDs, or None when the extension is absent."""
        try:
            extension = self.certificate.extensions.get_extension_for_class(
                x509.ExtendedKeyUsage
            ).value
        except x509.ExtensionNotFound:
            return None
        return [usage.dotted_string for usage in extension]

    @property
    def can_authenticate(self) -> bool:
        """Whether the issuer marked this certificate for logon.

        A card also carries certificates for e-mail, EFS and document signing.
        Offering one of those to the server produces a rejected handshake with
        no useful diagnostic, so they are filtered out up front. An absent EKU
        means no restriction.
        """
        usages = self.extended_key_usage
        if usages is None:
            return True
        return bool({EKU_CLIENT_AUTH, EKU_SMARTCARD_LOGON}.intersection(usages))

    @property
    def is_suitable(self) -> bool:
        return self.can_authenticate and not self.is_expired and not self.is_self_signed

    def principal_name(self) -> str | None:
        """UPN from subjectAltName, which is what an RRAS/NPS server expects."""
        try:
            san = self.certificate.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value
        except x509.ExtensionNotFound:
            return None
        for name in san.get_values_for_type(x509.OtherName):
            # id-ms-upn 1.3.6.1.4.1.311.20.2.3, value is a DER-encoded UTF8String
            if name.type_id.dotted_string == "1.3.6.1.4.1.311.20.2.3":
                raw = name.value
                if len(raw) >= 2 and raw[0] in (0x0C, 0x1B):
                    return raw[2:].decode("utf-8", "replace")
                return raw.decode("utf-8", "replace")
        for value in san.get_values_for_type(x509.RFC822Name):
            return value
        return None

    def __str__(self) -> str:
        upn = self.principal_name()
        return f"{self.label or '(no label)'} {self.subject}" + (
            f" upn={upn}" if upn else ""
        )


@dataclass
class Identity(CardCertificate):
    """A certificate whose private key is present on the token."""

    key_type: str  # "rsa" or "ec"
    key_handle: object

    def __str__(self) -> str:
        upn = self.principal_name()
        return f"{self.label or '(no label)'} [{self.key_type}] {self.subject}" + (
            f" upn={upn}" if upn else ""
        )


def discover_modules() -> list[str]:
    return [path for path in KNOWN_MODULES if os.path.exists(path)]


class Token:
    def __init__(self, module_path: str | None = None):
        self._lib = PyKCS11.PyKCS11Lib()
        self._session = None
        self.info: TokenInfo | None = None
        if module_path is None:
            module_path = self._autodetect()
        else:
            self._load(module_path)
        self.module_path = module_path
        logger.debug("loaded PKCS#11 module %s", module_path)

    def _load(self, module_path: str) -> None:
        try:
            self._lib.load(module_path)
        except PyKCS11.PyKCS11Error as exc:
            raise TokenError(f"cannot load {module_path}: {exc}") from exc

    def _autodetect(self) -> str:
        """Pick the module that answers for the card that is actually inserted.

        Several middlewares can be installed side by side, and each one only
        speaks to its own cards: SafeNet reports no slots for a JaCarta PKI card
        and vice versa. Taking the first installed module would fail with "no
        token present" while a perfectly readable card sits in the reader.
        """
        found = discover_modules()
        if not found:
            raise TokenError(
                "PKCS#11 module not found. Install the card middleware "
                "or pass --pkcs11-module explicitly."
            )
        fallback = None
        for path in found:
            try:
                self._load(path)
                if self._lib.getSlotList(tokenPresent=True):
                    return path
            except (TokenError, PyKCS11.PyKCS11Error):
                logger.debug("PKCS#11 module %s is unusable, skipping", path)
                continue
            if fallback is None:
                fallback = path
        if fallback is None:
            raise TokenError("no installed PKCS#11 module could be loaded")
        # No card anywhere; open() will report it with the usual wording.
        self._load(fallback)
        return fallback

    def slots(self) -> list[TokenInfo]:
        result = []
        for slot in self._lib.getSlotList(tokenPresent=True):
            try:
                info = self._lib.getTokenInfo(slot)
            except PyKCS11.PyKCS11Error:
                continue
            flags = info.flags
            result.append(
                TokenInfo(
                    slot=slot,
                    label=info.label.strip(),
                    serial=info.serialNumber.strip(),
                    pin_count_low=bool(flags & PyKCS11.CKF_USER_PIN_COUNT_LOW),
                    pin_final_try=bool(flags & PyKCS11.CKF_USER_PIN_FINAL_TRY),
                    pin_locked=bool(flags & PyKCS11.CKF_USER_PIN_LOCKED),
                )
            )
        return result

    def open(self, slot: int | None = None) -> TokenInfo:
        """Open a session without logging in, so certificates can be listed."""
        available = self.slots()
        if not available:
            raise TokenError("no token present — is the card inserted?")
        chosen = next((info for info in available if info.slot == slot), available[0])
        try:
            self._session = self._lib.openSession(
                chosen.slot, PyKCS11.CKF_SERIAL_SESSION
            )
        except PyKCS11.PyKCS11Error as exc:
            raise TokenError(
                f"cannot open session on slot {chosen.slot}: {exc}"
            ) from exc
        self.info = chosen
        logger.debug("session open on slot %s", chosen.slot)
        return chosen

    def login(self, pin: str) -> None:
        if self._session is None:
            raise TokenError("session is not open")
        # A wrong PIN can burn the last attempt and leave the card unusable, so
        # the card's own warning becomes a hard stop rather than a log line.
        if self.info.pin_locked:
            raise TokenError(
                f"the PIN on token {self.info.label!r} is locked; unlock it with "
                "the card management tool before connecting"
            )
        if self.info.pin_final_try:
            raise TokenError(
                f"token {self.info.label!r} reports it is on its FINAL PIN "
                "attempt; refusing to try in case the PIN is wrong"
            )
        if self.info.pin_count_low:
            logger.warning(
                "token %r reports a low remaining PIN attempt count", self.info.label
            )
        try:
            self._session.login(pin)
        except PyKCS11.PyKCS11Error as exc:
            raise TokenError(f"login failed: {exc}") from exc
        logger.debug("logged in to %r", self.info.label)

    def close(self) -> None:
        if self._session is not None:
            try:
                self._session.logout()
            except PyKCS11.PyKCS11Error:
                pass
            self._session.closeSession()
            self._session = None

    def certificates(self) -> list[CardCertificate]:
        """List the certificates on the token without logging in.

        Cards keep certificates as public objects but hide private keys behind
        C_Login, so the choice of certificate can be offered before a PIN.
        """
        if self._session is None:
            raise TokenError("session is not open")
        found = []
        for handle in self._session.findObjects(
            [(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)]
        ):
            value, ckaid, label = self._attributes(
                handle, [PyKCS11.CKA_VALUE, PyKCS11.CKA_ID, PyKCS11.CKA_LABEL]
            )
            if not value:
                continue
            cert_der = _as_bytes(value)
            label = _as_text(label)
            try:
                certificate = x509.load_der_x509_certificate(cert_der)
            except ValueError:
                logger.debug("skipping unparsable certificate %r", label)
                continue
            found.append(
                CardCertificate(label, _as_bytes(ckaid), cert_der, certificate)
            )
        return found

    def _pair(self, entry: CardCertificate) -> Identity | None:
        key = self._find_private_key(entry.ckaid)
        if key is None:
            return None
        key_handle, key_type = key
        return Identity(
            entry.label,
            entry.ckaid,
            entry.cert_der,
            entry.certificate,
            key_type,
            key_handle,
        )

    def identity_for(self, entry: CardCertificate) -> Identity:
        """Pair a chosen certificate with its on-card key; requires a login."""
        identity = self._pair(entry)
        if identity is None:
            raise TokenError(
                f"certificate {entry.label!r} has no private key on this token"
            )
        return identity

    def identities(self) -> list[Identity]:
        """Certificates usable for authentication; requires a login first."""
        found = []
        for entry in self.certificates():
            identity = self._pair(entry)
            if identity is None:
                logger.debug(
                    "certificate %r has no private key on the token", entry.label
                )
                continue
            found.append(identity)
        return found

    def _attributes(self, handle, attributes):
        try:
            return self._session.getAttributeValue(handle, attributes)
        except PyKCS11.PyKCS11Error:
            return [None] * len(attributes)

    def _find_private_key(self, ckaid: bytes):
        template = [(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)]
        if ckaid:
            template.append((PyKCS11.CKA_ID, ckaid))
        for handle in self._session.findObjects(template):
            (key_type,) = self._attributes(handle, [PyKCS11.CKA_KEY_TYPE])
            if key_type == PyKCS11.CKK_RSA:
                return handle, "rsa"
            if key_type == PyKCS11.CKK_EC:
                return handle, "ec"
        return None

    def sign(self, identity: Identity, digest: bytes, hash_name: str) -> bytes:
        """Sign a pre-computed digest on the card.

        RSA produces a PKCS#1 v1.5 signature; EC produces a DER-encoded ECDSA
        signature, converted from the raw r||s the token returns.
        """
        if self._session is None:
            raise TokenError("session is not open")
        if identity.key_type == "rsa":
            prefix = _DIGEST_INFO.get(hash_name)
            if prefix is None:
                raise TokenError(f"unsupported hash for RSA signing: {hash_name}")
            mechanism = PyKCS11.Mechanism(PyKCS11.CKM_RSA_PKCS, None)
            payload = prefix + digest
        else:
            mechanism = PyKCS11.Mechanism(PyKCS11.CKM_ECDSA, None)
            payload = digest
        try:
            signature = bytes(
                self._session.sign(identity.key_handle, payload, mechanism)
            )
        except PyKCS11.PyKCS11Error as exc:
            raise TokenError(f"on-card signing failed: {exc}") from exc
        if identity.key_type == "ec":
            half = len(signature) // 2
            r = int.from_bytes(signature[:half], "big")
            s = int.from_bytes(signature[half:], "big")
            signature = encode_dss_signature(r, s)
        return signature
