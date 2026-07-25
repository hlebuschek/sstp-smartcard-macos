"""Drive the EAP-TLS handshake engine against a real OpenSSL server.

The smart card is replaced by a software key so the TLS 1.2 implementation can
be validated on its own, including client certificate authentication and the
CertificateVerify signature path.

    python tools/tls_selftest.py [--cipher ECDHE-RSA-AES128-SHA256]
"""

from __future__ import annotations

import argparse
import datetime
import os
import socket
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from sstp import log
from sstp.tls import TlsClient

logger = log.get("selftest")


class SoftwareIdentity:
    def __init__(self, cert_der: bytes, private_key, key_type: str):
        self.cert_der = cert_der
        self.key_type = key_type
        self.private_key = private_key


class SoftwareToken:
    """Stands in for the PKCS#11 token, signing a pre-computed digest."""

    def sign(self, identity, digest: bytes, hash_name: str) -> bytes:
        algorithm = {
            "sha1": hashes.SHA1(),
            "sha256": hashes.SHA256(),
            "sha384": hashes.SHA384(),
            "sha512": hashes.SHA512(),
        }[hash_name]
        prehashed = Prehashed(algorithm)
        if identity.key_type == "rsa":
            return identity.private_key.sign(digest, padding.PKCS1v15(), prehashed)
        return identity.private_key.sign(digest, ec.ECDSA(prehashed))


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _key_usage(**overrides) -> x509.KeyUsage:
    flags = dict.fromkeys(
        (
            "digital_signature",
            "content_commitment",
            "key_encipherment",
            "data_encipherment",
            "key_agreement",
            "key_cert_sign",
            "crl_sign",
            "encipher_only",
            "decipher_only",
        ),
        False,
    )
    flags.update(overrides)
    return x509.KeyUsage(**flags)


def _issue(subject_name, issuer_key_pair, public_key, is_ca, san=None, eku=None):
    """Issue a certificate with the extensions RFC 5280 path validation expects.

    A bare certificate is enough for a handshake but not for chain building:
    the verifier rejects a leaf without an authority key identifier.
    """
    issuer_certificate, issuer_key = issuer_key_pair
    issuer_name = issuer_certificate.subject if issuer_certificate else subject_name
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(issuer_name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), False)
    )
    if is_ca:
        builder = builder.add_extension(
            _key_usage(key_cert_sign=True, crl_sign=True), critical=True
        )
    else:
        builder = builder.add_extension(
            _key_usage(digital_signature=True, key_encipherment=True), critical=True
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                issuer_key.public_key()
            ),
            critical=False,
        )
    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False
        )
    if eku:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    return builder.sign(issuer_key, hashes.SHA256())


def build_pki(directory: str, client_key_type: str):
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_cert = _issue(_name("selftest CA"), (None, ca_key), ca_key.public_key(), True)
    ca = (ca_cert, ca_key)

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_cert = _issue(
        _name("localhost"),
        ca,
        server_key.public_key(),
        False,
        san="localhost",
        eku=[ExtendedKeyUsageOID.SERVER_AUTH],
    )

    if client_key_type == "rsa":
        client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    else:
        client_key = ec.generate_private_key(ec.SECP256R1())
    client_cert = _issue(
        _name("selftest client"),
        ca,
        client_key.public_key(),
        False,
        eku=[ExtendedKeyUsageOID.CLIENT_AUTH],
    )

    def write(name: str, data: bytes) -> str:
        path = os.path.join(directory, name)
        with open(path, "wb") as handle:
            handle.write(data)
        return path

    paths = {
        "ca": write("ca.pem", ca_cert.public_bytes(serialization.Encoding.PEM)),
        "server_cert": write(
            "server.pem", server_cert.public_bytes(serialization.Encoding.PEM)
        ),
        "server_key": write(
            "server.key",
            server_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ),
        ),
    }
    identity = SoftwareIdentity(
        client_cert.public_bytes(serialization.Encoding.DER), client_key, client_key_type
    )
    return paths, identity


def run(port: int, cipher: str | None, client_key_type: str, verify: bool) -> int:
    with tempfile.TemporaryDirectory() as directory:
        paths, identity = build_pki(directory, client_key_type)

        command = [
            "openssl", "s_server",
            "-accept", str(port),
            "-cert", paths["server_cert"],
            "-key", paths["server_key"],
            "-CAfile", paths["ca"],
            "-Verify", "1",
            "-tls1_2",
            "-naccept", "1",
            "-quiet",
        ]
        if cipher:
            command += ["-cipher", cipher]

        server = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
        try:
            time.sleep(1.0)
            if server.poll() is not None:
                print(server.stdout.read().decode(errors="replace"))
                return 1

            client = TlsClient(
                identity,
                SoftwareToken(),
                server_name="localhost",
                ca_file=paths["ca"] if verify else None,
                verify=verify,
            )
            sock = socket.create_connection(("127.0.0.1", port), timeout=15)
            sock.sendall(client.start())

            deadline = time.time() + 15
            while not client.handshake_complete and time.time() < deadline:
                data = sock.recv(65536)
                if not data:
                    raise RuntimeError("server closed the connection")
                out = client.feed(data)
                if out:
                    sock.sendall(out)

            if not client.handshake_complete:
                raise RuntimeError("handshake timed out")

            msk = client.export_msk()
            print(f"  cipher suite : {client.suite.name}")
            print(f"  server cert  : {client.server_certificate.subject.rfc4514_string()}")
            print(f"  client key   : {identity.key_type}")
            print(f"  MSK[0:16]    : {msk[:16].hex()}")
            print(f"  MSK length   : {len(msk)}")
            sock.close()
            return 0
        finally:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=14433)
    parser.add_argument("--cipher", default=None)
    parser.add_argument("--key-type", choices=["rsa", "ec"], default="rsa")
    parser.add_argument(
        "--verify", action="store_true", help="verify the server chain against the test CA"
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    log.setup(args.verbose)
    label = args.cipher or "server default"
    chain = ", verifying chain" if args.verify else ""
    print(f"TLS 1.2 handshake self-test ({label}, {args.key_type} client key{chain})")
    try:
        code = run(args.port, args.cipher, args.key_type, args.verify)
    except Exception as exc:
        print(f"  FAILED: {exc}")
        return 1
    print("  OK" if code == 0 else "  FAILED")
    return code


if __name__ == "__main__":
    sys.exit(main())
