"""An ephemeral certificate authority, trusted only inside one sandbox run.

To say "the tool sent YOUR DATA to that host" rather than merely "the tool
contacted that host", the proxy has to see inside TLS. That means terminating
the connection with a certificate the sandboxed tool will accept, which means
a CA.

A CA is the most dangerous artifact this project could produce, so this one is
built to be worthless to steal:

  - It is generated in memory at the start of a run and discarded at the end.
  - The private key is never written to the repository, never committed, and
    never reused between runs.
  - It is valid for hours, not years.
  - Its subject says plainly what it is, so a human who ever sees it in a
    trust store knows immediately that something is wrong.
  - Only the sandbox container is told to trust it. Nothing on the host does.

If this CA leaked it would authorise nothing, because by the time anyone could
use it the run is over and the key is gone.
"""

from __future__ import annotations

import datetime
import ipaddress
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

#: Deliberately alarming. This name should never appear in a real trust store,
#: and if it does, whoever finds it should know at a glance what happened.
CA_COMMON_NAME = "SayDo sandbox inspection CA (ephemeral, single run)"


class SandboxCA:
    """A short-lived CA plus leaf certificates minted on demand per host."""

    def __init__(self, hours=6):
        self._lock = threading.Lock()
        self._leaves = {}
        self.key = rsa.generate_private_key(public_exponent=65537,
                                            key_size=2048)
        now = datetime.datetime.now(datetime.timezone.utc)
        self._not_before = now - datetime.timedelta(minutes=5)
        self._not_after = now + datetime.timedelta(hours=hours)

        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, CA_COMMON_NAME),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SayDo"),
        ])
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(self._not_before)
            .not_valid_after(self._not_after)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0),
                           critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False), critical=True)
            # OpenSSL 3 will not build a chain without these: the CA must
            # publish a subject key identifier and each leaf must point back
            # at it. Omitting them produces "Missing Authority Key
            # Identifier" at the client, which looks like a trust failure
            # rather than a malformed certificate.
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(
                    self.key.public_key()), critical=False)
            .sign(self.key, hashes.SHA256())
        )

    def ca_pem(self):
        """The certificate to install in the sandbox's trust stores."""
        return self.cert.public_bytes(serialization.Encoding.PEM)

    def leaf_pem(self, host):
        """(cert_pem, key_pem) for `host`, minted once and reused in-run."""
        with self._lock:
            if host in self._leaves:
                return self._leaves[host]

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        try:
            alt = x509.IPAddress(ipaddress.ip_address(host))
        except ValueError:
            alt = x509.DNSName(host)

        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, host[:64])]))
            .issuer_name(self.cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(self._not_before)
            .not_valid_after(self._not_after)
            .add_extension(x509.SubjectAlternativeName([alt]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                           critical=True)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.key.public_key()), critical=False)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False)
            .add_extension(x509.ExtendedKeyUsage(
                [x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(self.key, hashes.SHA256())
        )
        pair = (
            cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()),
        )
        with self._lock:
            self._leaves[host] = pair
        return pair
