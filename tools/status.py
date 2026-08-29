"""Reduce a signed receipt to a saydo/status: the artifact an agent reads.

A receipt is the proof, but it is a whole ledger. An agent choosing a tool at
call time needs a verdict it can read in one shot and act on -- and it needs
it to be honest about being a summary, not the evidence. That is saydo/status:
a compact, model-legible object derived deterministically from the receipt and
anchor, carrying a pointer back to the receipt for anyone who wants the proof.

It is refusal-first. A tool that was never put under warrant, or whose receipt
is unsigned or non-conformant, does NOT come back "warranted". The `verdict`
and the `advice` tell an agent plainly what to do, and default to caution.

The status is a convenience, not a trust root. It says so, in `trust`, and it
names the receipt so the agent (or a human) can verify without believing this
summary or SayDo.

Usage:
    python status.py <receipt.jsonl> <anchor.json> [--receipt-url URL]
"""

from __future__ import annotations

import argparse
import json
import sys

# invariant type -> a plain phrase a model and a person both read the same way.
_ENVELOPE = {
    "no-network": lambda p: "makes no network calls",
    "network-allowlist": lambda p: "reaches only " + ", ".join(
        (p or {}).get("hosts", [])) if (p or {}).get("hosts") else
        "reaches only a declared set of hosts",
    "no-write": lambda p: "writes no files",
    "write-scope": lambda p: "writes only under " + ", ".join(
        (p or {}).get("paths", [])) if (p or {}).get("paths") else
        "writes only within a declared path",
    "read-scope": lambda p: "reads only its declared inputs",
    "no-subprocess": lambda p: "starts no other programs",
    "deterministic": lambda p: "returns the same output for the same input",
    "error-as-value": lambda p: "returns errors instead of crashing",
    "refusal-tool": lambda p: "states its own limits before acting",
    "property": lambda p: (p or {}).get("statement", "holds a declared property"),
}


def _rows(receipt_lines):
    return [json.loads(l) for l in receipt_lines if l.strip()]


def _phrase(inv_type, params):
    fn = _ENVELOPE.get(inv_type)
    try:
        return fn(params) if fn else inv_type
    except Exception:
        return inv_type


def build(receipt_lines, anchor, receipt_url=None):
    rows = _rows(receipt_lines)
    opening = next((r for r in rows if r.get("type") == "receipt-open"), {})
    monitor = next((r for r in rows if r.get("type") == "monitor"), {})
    verdicts = [r for r in rows if r.get("type") == "verdict"]
    findings = [r for r in rows if r.get("type") == "finding"]
    subject = opening.get("subject", {})

    passed = [v for v in verdicts if v["verdict"] == "pass"]
    failed = [v for v in verdicts if v["verdict"] == "fail"]
    notcov = [v for v in verdicts if v["verdict"] == "not-covered"]

    signed = bool(anchor.get("signature"))
    conformant = bool(anchor.get("conformant"))

    if not conformant or failed or findings:
        verdict = "failing"
    elif not signed:
        verdict = "draft"
    else:
        verdict = "warranted"

    # The envelope: the promises that HELD, in plain words, deduped in order.
    envelope, seen = [], set()
    for v in passed:
        phrase = _phrase(v["invariantType"], None)
        if phrase not in seen:
            seen.add(phrase)
            envelope.append(phrase)

    name = subject.get("name", "?")
    version = subject.get("version", "")
    if verdict == "warranted":
        summary = "{} {}: warranted. {} checks held; {}.".format(
            name, version, len(passed),
            "; ".join(envelope[:4]) or "no behavioral claims")
        advice = ("Safe to use within its declared envelope ({}). This is a "
                  "summary; the proof is the signed receipt.".format(
                      "; ".join(envelope) or "none"))
    elif verdict == "failing":
        reasons = [f["invariant"] + ": " + f["evidence"] for f in failed]
        reasons += [f["kind"] + " (" + f.get("tool", "") + ")" for f in findings]
        summary = "{} {}: NOT warranted. {} declared behavior(s) failed.".format(
            name, version, len(failed) + len(findings))
        advice = ("Do not rely on this tool's declared behavior. It does more "
                  "than it declares: {}. Verify the receipt.".format(
                      "; ".join(reasons[:4])))
    else:  # draft
        summary = "{} {}: unsigned draft. Tested but not signed.".format(
            name, version)
        advice = ("Treat as unverified. A draft receipt is not a warrant; it "
                  "carries no signature. Do not present it as warranted.")

    status = {
        "saydoStatus": "0.1.0",
        "subject": {"name": name, "version": version,
                    "purl": subject.get("purl", "")},
        "verdict": verdict,
        "conformant": conformant,
        "summary": summary,
        "advice": advice,
        "checks": {"passed": len(passed), "failed": len(failed),
                   "notCovered": len(notcov),
                   "failedDetail": [{"invariant": f["invariant"],
                                     "evidence": f["evidence"]} for f in failed]},
        "envelope": envelope,
        "caveat": ("Behavior was observed, not sandboxed. A tool built to "
                   "evade observation may act unseen; the proof is the receipt, "
                   "not this summary."),
        "receipt": {"head": anchor.get("head"),
                    "url": receipt_url,
                    "verify": "Recompute the chain and signature in a browser; "
                              "no account, no trust in SayDo."},
        "signature": ({"algorithm": anchor["signature"].get("algorithm"),
                       "keyId": anchor["signature"].get("keyId"),
                       "signer": anchor["signature"].get("signer"),
                       "checkedHere": False}
                      if signed else None),
        "trust": ("This status is a convenience for fast gating, not evidence. "
                  "The evidence is the signed receipt named above; verify it."),
    }
    return status


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("receipt")
    ap.add_argument("anchor")
    ap.add_argument("--receipt-url")
    ap.add_argument("-o", "--out")
    args = ap.parse_args()
    with open(args.receipt, encoding="utf-8") as fh:
        lines = fh.readlines()
    with open(args.anchor, encoding="utf-8") as fh:
        anchor = json.load(fh)
    status = build(lines, anchor, args.receipt_url)
    text = json.dumps(status, indent=2, ensure_ascii=False) + "\n"
    if args.out:
        with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        print("{}: {}".format(args.out, status["verdict"]))
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    main()
