"""How an agent gates a tool on its saydo/status. The 'it already works' demo.

This is the point of the whole distribution story: an agent, choosing a tool
at call time, reads the compact status and decides. No document parsing, no
trust in SayDo -- just a verdict and an envelope it can act on, with a receipt
to verify if it wants the proof.

The policy here is the one a cautious agent would run:

    warranted  -> USE, and stay inside the declared envelope
    draft      -> USE WITH CAUTION: tested but unsigned, so not vouched-for
    failing    -> REFUSE: it does more than it declares
    unknown    -> REFUSE by default: never put under warrant

Refusal-first: the default for anything not clearly warranted is to hold back.
That is the same discipline the tools themselves ship with.

Run it against the receipts in this repo:
    python examples/agent_gate.py
"""

from __future__ import annotations

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import status as status_mod


def status_for(name):
    """The saydo/status for a server whose receipt is in this repo, or an
    'unknown' status when no receipt exists."""
    rec = os.path.join(ROOT, "receipts", name + ".receipt.jsonl")
    anc = os.path.join(ROOT, "receipts", name + ".anchor.json")
    if not (os.path.exists(rec) and os.path.exists(anc)):
        return {"verdict": "unknown",
                "subject": {"name": name},
                "summary": "{}: no SayDo receipt found.".format(name),
                "advice": "Never put under warrant. Treat as untrusted.",
                "envelope": []}
    with open(rec, encoding="utf-8") as fh:
        lines = fh.readlines()
    with open(anc, encoding="utf-8") as fh:
        anchor = json.load(fh)
    return status_mod.build(lines, anchor,
                            receipt_url="receipts/{}.receipt.jsonl".format(name))


def gate(status):
    """The agent's decision and the one-line reason it would log."""
    v = status["verdict"]
    if v == "warranted":
        return "USE", "within envelope: " + "; ".join(status["envelope"])
    if v == "draft":
        return "CAUTION", "tested but unsigned; not vouched-for"
    if v == "failing":
        fd = status.get("checks", {}).get("failedDetail", [])
        why = "; ".join(f["invariant"] for f in fd) or "declared behavior failed"
        return "REFUSE", "exceeds its declaration: " + why
    return "REFUSE", "no warrant on record"


def main():
    # A mix: a warranted tool, two that fail, and one never tested.
    candidates = ["certivl", "node-fetcher", "malserver", "some-random-tool"]
    print("agent tool-selection gate\n" + "-" * 60)
    for name in candidates:
        st = status_for(name)
        decision, reason = gate(st)
        print("{:<16} {:<8} {}".format(name, decision, reason))
    print("-" * 60)
    print("An agent calls only what it can rely on. The status is the read;\n"
          "the signed receipt is the proof, verifiable without trusting us.")


if __name__ == "__main__":
    main()
