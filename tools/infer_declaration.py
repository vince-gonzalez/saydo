"""Propose a draft declaration from a capture, so onboarding a server is fast.

Authoring a declaration by hand does not scale to a registry of thousands of
servers. This infers a CONSERVATIVE skeleton from the captured tool
definitions: it assumes the tightest envelope a well-behaved tool would honor
-- no network, no writes, no subprocess, errors returned as values, and a
refusal tool if one is present -- and binds it to the real digests.

Every inferred invariant is a HYPOTHESIS, not a finding. The skeleton is meant
to be run: the harness will FAIL exactly the invariants the tool actually
exceeds, and those failures are the map of what the tool really does. That is
how mcp-server-fetch's undeclared `node` subprocess surfaced -- a conservative
skeleton, tested, told the truth. A human then keeps the invariants that hold,
relaxes the ones that were too strict for good reason (a fetcher really does
need the network), and signs the result.

The output is status "draft" and unsigned by construction. Inference proposes;
it never asserts conformance.

Usage:
    python infer_declaration.py <capture.json> [--purl pkg:...] [--supplier X]
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid

_NS = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")

# Tool names that, by convention, are the refusal/guard tool.
_REFUSAL_NAMES = ("scope", "guard", "about", "capabilities")


def infer(capture, purl=None, supplier=None):
    tools = capture["tools"]
    names = [t["name"] for t in tools]
    server = capture.get("server", {})
    name = server.get("name") or "unknown"
    version = server.get("version") or "0.0.0"
    purl = purl or "pkg:unknown/{}@{}".format(name, version)

    invariants = [
        {"id": "network.none", "type": "no-network", "appliesTo": ["*"],
         "note": "HYPOTHESIS: assumes no egress. Relax to network-allowlist "
                 "if the tool legitimately calls out."},
        {"id": "writes.none", "type": "no-write", "appliesTo": ["*"],
         "note": "HYPOTHESIS: assumes no filesystem writes."},
        {"id": "subprocess.none", "type": "no-subprocess", "appliesTo": ["*"],
         "note": "HYPOTHESIS: assumes no child processes."},
        {"id": "errors.are-values", "type": "error-as-value", "appliesTo": ["*"],
         "note": "HYPOTHESIS: assumes malformed input returns an error value "
                 "rather than crashing the transport."},
    ]
    refusal = next((n for n in names if n.lower() in _REFUSAL_NAMES), None)
    if refusal:
        invariants.insert(0, {
            "id": "refusal.{}".format(refusal), "type": "refusal-tool",
            "appliesTo": ["*"], "params": {"tool": refusal},
            "note": "HYPOTHESIS: assumes {} is a no-I/O refusal tool.".format(
                refusal)})

    return {
        "declarationVersion": "0.1.0",
        "serialNumber": "urn:uuid:{}".format(
            uuid.uuid5(_NS, "saydo-inferred:" + purl)),
        "createdAt": "1970-01-01T00:00:00Z",
        "status": "draft",
        "subject": {
            "kind": "mcp-server", "name": name, "version": version,
            "supplier": {"name": supplier or "unknown"},
            "artifacts": [{"type": "other", "identifier": purl}],
        },
        "binding": {"tools": [{"name": t["name"],
                               "definitionDigest": t["definitionDigest"]}
                              for t in tools]},
        "invariants": invariants,
        "canonicalization": "rfc8785",
        "notes": ("Inferred skeleton: every invariant is a conservative "
                  "HYPOTHESIS, not a finding. Run the harness; the failures "
                  "are the map of what this tool actually does. Then keep what "
                  "held, relax what was too strict for a real reason, and sign."),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("capture")
    ap.add_argument("--purl")
    ap.add_argument("--supplier")
    ap.add_argument("-o", "--out")
    args = ap.parse_args()
    with open(args.capture, encoding="utf-8") as fh:
        capture = json.load(fh)
    doc = infer(capture, args.purl, args.supplier)
    text = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
    if args.out:
        with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        print("{}: {} tools, {} hypotheses (all draft)".format(
            args.out, len(doc["binding"]["tools"]), len(doc["invariants"])))
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    main()
