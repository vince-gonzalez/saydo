# WARRANT receipts — how a conformance run becomes a receipt anyone can check

A receipt turns a conformance report into a record a stranger verifies without
an account and without trusting the issuer. It is a hash-chained JSONL ledger
plus a genesis anchor, built with THE RECORD engine unchanged.

## The chain

    canonical(row) = json.dumps(row, sort_keys=True, ensure_ascii=False,
                                separators=(",", ":"))
    prev           = sha256(GENESIS.encode()).hexdigest()
    row_hash       = sha256((prev + canonical(row_without_hashes))
                            .encode("utf-8")).hexdigest()
    seq            = 1, 2, 3, ... monotonic

These are the exact rules THE RECORD's `verify_chain.py` enforces. That
verifier, unmodified except its GENESIS constant (which is the per-receipt
anchor, not part of the algorithm), verifies a WARRANT receipt and reproduces
its head. The reuse is real, not a reimplementation of the same idea.

## The genesis anchor binds the chain to what it attests

    GENESIS = "WARRANT-RECEIPT/0.1.0|<declaration serial>|<subject purl>"

A receipt for `certivl@0.2.0` under one declaration cannot be spliced onto
another subject's chain: the head would not reproduce under the other's
genesis. The anchor (genesis + head) is the trust root and travels separately
from the ledger — published, and in a declared receipt, signed over the head.

## Rows

    receipt-open   version, declaration serial, subject, harness id, time
    capture        the exact tool definitions and their digests
    monitor        what the monitor observes and, stated plainly, does not
    verdict        one per declared invariant: id, type, verdict, evidence
    finding        one per unanticipated finding (may be none)
    receipt-close  conformant, tally, row count

Every verdict and every finding is its own row, so a tampered verdict breaks
the chain at exactly that row and the verifier names it.

## The browser verifier

`verifier/index.html` is self-contained: no network request, no external
script, no account. It recomputes the whole chain with `crypto.subtle` and a
JavaScript canonicalizer that is byte-identical to the Python above — proven
by the head it computes matching the head Python wrote. It reports three
failure modes distinctly:

  - an edited row: `row_hash does not match its own contents`
  - a deleted or reordered row: `sequence is N, expected M`
  - a valid chain re-anchored to a false head: `head does not match the anchor`

and renders the subject, the verdict table, and any findings for a human to
read. It ships with a real receipt embedded so it verifies itself on load.

## Generate one

    python receipt.py <report.json> <declaration.json> <capture.json> \
        <out_dir> [--at <iso8601>]

`--at` fixes the generated-at stamp so a committed receipt is reproducible.

## What a green receipt does and does not say

It says: this conformance run's observations stayed inside the declared
envelope, and this record has not been altered since. It does not say the tool
is safe, correct, or good — only that what was declared was tested and held,
and that the evidence is tamper-evident. The monitor's ceiling (Python
runtime, not the kernel; not a sandbox) is stated in the receipt itself.

## Signing

A receipt's head commits to its whole chain, so signing the head signs the
receipt. `receipt.py --sign <private.jwk>` adds an Ed25519 signature to the
anchor:

    "signature": {
      "role": "supplier", "algorithm": "Ed25519",
      "keyId": "urn:fkeys:saydo:key:f-keys-poc",
      "publicKey": "<raw Ed25519 public key, base64url>",
      "covers": "head", "signedAt": "...",
      "signer": "F-Keys Creative LLC", "value": "<signature, base64url>"
    }

The public key travels in the anchor, so the browser verifier checks the
signature with nothing else: it recomputes the head, then verifies the
Ed25519 signature over it with `crypto.subtle`. A valid signature over a
verified head means this exact chain was signed by the holder of that key. An
invalid signature fails the receipt even when the chain itself verifies; a
browser without Ed25519 in WebCrypto reports the signature as present but
unchecked rather than implying it passed.

`keygen.py` generates the keypair as JWK. The current key
(`urn:fkeys:saydo:key:f-keys-poc`) is a PROOF-OF-CONCEPT key: the private
half is gitignored and lives only on the build machine, and it is not the
LLC's production signing identity. A production key is managed (HSM or a
managed KMS key), rotated, and its public key published at a controlled URL.
Trust a receipt only as far as you trust the key in its anchor.
