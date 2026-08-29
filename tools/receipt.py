"""Turn a conformance report into a hash-chained WARRANT receipt.

The receipt is a JSONL ledger built with THE RECORD engine, verbatim:

    canonical(row) = json.dumps(row, sort_keys=True, ensure_ascii=False,
                                separators=(",", ":"))
    prev           = sha256(GENESIS.encode()).hexdigest()          # genesis
    row_hash       = sha256((prev + canonical(row_without_hashes))
                            .encode("utf-8")).hexdigest()          # per row
    seq            = 1, 2, 3, ...                                   # monotonic

These are the exact rules THE RECORD's verify_chain.py enforces, so that
verifier -- and the browser verifier shipped here -- validate a WARRANT
receipt without modification. Nothing about the receipt is WARRANT-specific
at the chain level; the behavioral content lives in the rows.

The genesis anchor binds the chain to what it attests: it names the
declaration serial and the subject artifact, so a receipt for one tool cannot
be spliced onto another's chain -- the head hash would not reproduce under
the other's genesis.

    GENESIS = "WARRANT-RECEIPT/0.1.0|<declaration serial>|<subject purl>"

The head (the last row's row_hash) is the receipt's identity. In a draft
receipt it is unsigned; a declared receipt carries a supplier signature over
the head, exactly as a declared declaration is signed over its canonical form.

The rows, in order:
    1  receipt-open      version, declaration serial, subject, harness id
    2  capture           the exact tool definitions and their digests
    3  monitor           what the monitor observes and, plainly, does not
    k  verdict           one per declared invariant: id, type, verdict, why
    .  finding           one per unanticipated finding (may be none)
    N  receipt-close     conformant, tally, row count

Usage:
    python receipt.py <report.json> <declaration.json> <capture.json> \
        <out_dir> [--at <iso8601>]
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os


def _b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64u_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sign_head(head_hex, private_jwk_path, signed_at):
    """An Ed25519 signature over the receipt head, as a signature block.

    The head commits to the whole chain, so signing it signs the receipt.
    Returns the block for anchor.signature, carrying the public key inline so
    a verifier needs nothing but the receipt and the anchor.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey)

    with open(private_jwk_path, encoding="utf-8") as fh:
        jwk = json.load(fh)
    priv = Ed25519PrivateKey.from_private_bytes(_b64u_decode(jwk["d"]))
    signature = priv.sign(head_hex.encode("ascii"))
    return {
        "role": "supplier",
        "type": "jws-ed25519",
        "algorithm": "Ed25519",
        "keyId": jwk["kid"],
        "publicKey": jwk["x"],          # raw Ed25519 public key, base64url
        "covers": "head",
        "signedAt": signed_at,
        "signer": jwk.get("supplier", ""),
        "value": _b64u(signature),
    }


def canonical(row):
    # THE RECORD's canonical form. Not full RFC 8785 (no number
    # normalization); the receipt rows carry only strings, ints, and nested
    # objects/arrays, for which this is deterministic and matches the JS
    # canonicalizer in the browser verifier byte for byte.
    return json.dumps(row, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"))


def _sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class Chain:
    def __init__(self, genesis):
        self.genesis = genesis
        self.prev = _sha(genesis)
        self.seq = 0
        self.rows = []

    def add(self, body):
        """Append a row. body is the payload; seq/prev_hash/row_hash are set
        here so the row hashes exactly as verify_chain.py recomputes it."""
        self.seq += 1
        row = dict(body)
        row["seq"] = self.seq
        payload = canonical(row)                      # excludes the hashes
        row_hash = _sha(self.prev + payload)
        row["prev_hash"] = self.prev
        row["row_hash"] = row_hash
        self.prev = row_hash
        self.rows.append(row)
        return row

    @property
    def head(self):
        return self.prev


def build(report, declaration, capture, generated_at):
    subject = declaration["subject"]
    purl = subject["artifacts"][0]["identifier"]
    genesis = "WARRANT-RECEIPT/0.1.0|{}|{}".format(
        declaration["serialNumber"], purl)
    chain = Chain(genesis)

    chain.add({
        "type": "receipt-open",
        "receiptVersion": "0.1.0",
        "declarationSerial": declaration["serialNumber"],
        "declarationVersion": declaration["declarationVersion"],
        "declarationStatus": declaration["status"],
        "subject": {"name": subject["name"], "version": subject["version"],
                    "purl": purl,
                    "supplier": subject["supplier"]["name"]},
        "harness": {"version": report["harness_version"],
                    "monitor": report["monitor"]},
        "generatedAt": generated_at,
    })

    chain.add({
        "type": "capture",
        "protocolVersion": capture.get("protocolVersion", ""),
        "tools": [{"name": t["name"],
                   "definitionDigest": t["definitionDigest"]["value"],
                   "covers": t["definitionDigest"]["covers"]}
                  for t in capture["tools"]],
    })

    chain.add({
        "type": "monitor",
        "method": "cpython-audit-hook",
        "observes": ["filesystem open (read/write intent)",
                     "socket connect/getaddrinfo/bind/sendto",
                     "subprocess and os exec/spawn",
                     "filesystem-mutating os and shutil calls"],
        "does_not_observe": (
            "activity below the Python runtime: a native extension or a "
            "direct ctypes syscall is not seen. This is drift-and-accident "
            "evidence and refutation of false declarations by ordinary code. "
            "It is not a sandbox."),
    })

    for v in report["verdicts"]:
        chain.add({
            "type": "verdict",
            "invariant": v["id"],
            "invariantType": v["type"],
            "appliesTo": v["appliesTo"],
            "verdict": v["verdict"],
            "evidence": v["evidence"],
        })

    for f in report["findings"]:
        chain.add({
            "type": "finding",
            "kind": f["kind"],
            "tool": f.get("tool", ""),
            "detail": f["detail"],
        })

    chain.add({
        "type": "receipt-close",
        "conformant": report["conformant"],
        "tally": report["tally"],
        "rowCount": chain.seq + 1,   # this row included
    })

    anchor = {
        "receiptVersion": "0.1.0",
        "genesis": genesis,
        "subject": {"name": subject["name"], "version": subject["version"],
                    "purl": purl},
        "declarationSerial": declaration["serialNumber"],
        "conformant": report["conformant"],
        "rows": len(chain.rows),
        "head": chain.head,
        "signature": None,   # populated by main() when --sign is given
    }
    return chain, anchor


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("report")
    ap.add_argument("declaration")
    ap.add_argument("capture")
    ap.add_argument("out_dir")
    ap.add_argument("--at", default="1970-01-01T00:00:00Z",
                    help="generatedAt stamp; fixed by default so committed "
                         "receipts are reproducible")
    ap.add_argument("--sign", metavar="PRIVATE_JWK",
                    help="Ed25519 private-key JWK to sign the receipt head; "
                         "without it the receipt is an unsigned draft")
    args = ap.parse_args()

    with open(args.report, encoding="utf-8") as fh:
        report = json.load(fh)
    with open(args.declaration, encoding="utf-8") as fh:
        declaration = json.load(fh)
    with open(args.capture, encoding="utf-8") as fh:
        capture = json.load(fh)

    chain, anchor = build(report, declaration, capture, args.at)
    if args.sign:
        anchor["signature"] = sign_head(anchor["head"], args.sign, args.at)

    os.makedirs(args.out_dir, exist_ok=True)
    name = declaration["subject"]["name"]
    ledger_path = os.path.join(args.out_dir, name + ".receipt.jsonl")
    anchor_path = os.path.join(args.out_dir, name + ".anchor.json")
    with open(ledger_path, "w", encoding="utf-8", newline="\n") as fh:
        for row in chain.rows:
            fh.write(canonical(row) + "\n")
    with open(anchor_path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(anchor, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    signed = " SIGNED" if anchor["signature"] else " unsigned(draft)"
    print("{}: {} rows, conformant={}, head {}{}".format(
        name, len(chain.rows), anchor["conformant"], anchor["head"][:16],
        signed))


if __name__ == "__main__":
    main()
