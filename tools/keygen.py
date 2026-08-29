"""Generate the F-Keys signing keypair for SayDo receipts.

Ed25519, written as JWK (kty OKP, crv Ed25519), matching the signature model
TBOM uses. The private half goes to keys/<id>.private.jwk and is gitignored;
the public half and a keyId go to keys/<id>.public.jwk and are committed, so a
verifier has the public key without dereferencing anything.

This is a PROOF-OF-CONCEPT key. It is labeled F-Keys but it is not the LLC's
production signing identity: a real one is managed (an HSM or a managed KMS
key), rotated, and its public key is published at a stable, controlled URL.
Do not treat a receipt signed with this key as a production attestation.

Usage:
    python keygen.py [key_id]        # default id: f-keys-poc
"""

from __future__ import annotations

import base64
import json
import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEYS = os.path.join(ROOT, "keys")


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def main():
    key_id = sys.argv[1] if len(sys.argv) > 1 else "f-keys-poc"
    os.makedirs(KEYS, exist_ok=True)

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    raw_priv = priv.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption())
    raw_pub = pub.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    # keyId is a URN naming the PoC key. A production key would be a stable,
    # controlled URL; this is deliberately marked poc so no one mistakes it.
    kid = "urn:fkeys:saydo:key:{}".format(key_id)

    public_jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64u(raw_pub),
                  "kid": kid,
                  "use": "sig", "alg": "Ed25519",
                  "supplier": "F-Keys Creative LLC",
                  "note": "PROOF-OF-CONCEPT key, not the production signing "
                          "identity."}
    private_jwk = dict(public_jwk, d=b64u(raw_priv))

    priv_path = os.path.join(KEYS, key_id + ".private.jwk")
    pub_path = os.path.join(KEYS, key_id + ".public.jwk")
    if os.path.exists(priv_path):
        raise SystemExit("{} already exists; refusing to overwrite a private "
                         "key".format(priv_path))
    with open(priv_path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(private_jwk, fh, indent=2)
        fh.write("\n")
    with open(pub_path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(public_jwk, fh, indent=2)
        fh.write("\n")
    os.chmod(priv_path, 0o600)

    print("keyId:  {}".format(kid))
    print("private: {}  (gitignored -- keep it, this machine only)".format(
        os.path.relpath(priv_path, ROOT)))
    print("public:  {}  (committed)".format(os.path.relpath(pub_path, ROOT)))


if __name__ == "__main__":
    main()
