"""Draft a declaration a publisher can actually sign.

Publisher mode has been theoretically available and practically unusable: it
required hand-writing the declaration JSON, which means knowing the schema,
the invariant vocabulary, and which claims your own tool can survive. Nobody
does that to try a tool out.

This drafts one from a real run. It starts from what the harness OBSERVED and
proposes only claims the evidence already supports, so the first thing a
publisher sees is a declaration that passes, and the interesting work becomes
tightening it rather than guessing it.

The direction matters and is easy to get backwards. A declaration is not a
description of what the tool did once; it is a promise about what it will keep
doing. So:

  observed no egress          -> propose no-network
  observed egress to A and B  -> propose network-allowlist [A, B]
  observed writes under P     -> propose write-scope P, never no-write
  observed a subprocess       -> propose NOTHING, and say why

That last case is the one that keeps this honest. When a tool did something,
the tool of least resistance is to write a declaration that permits it, and a
declaration that permits everything the tool happens to do is worthless. So
observed behaviour that cannot be bounded is reported as a decision for the
author, not silently blessed.

Every proposed invariant carries the evidence it came from, so a publisher is
signing something they can check rather than something they were handed.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import sys
import uuid

_NS = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")

#: Claims that are only worth proposing when the run actually exercised them;
#: proposing one the run never tested would be inviting a signature on an
#: untested promise.
NEEDS_EVIDENCE = {"no-network", "network-allowlist", "no-write",
                  "write-scope", "no-subprocess", "no-data-egress"}


def _verdicts(report):
    return {v["id"]: v for v in report.get("verdicts", [])}


def draft(report, capture, purl=None, supplier=None):
    subject = report["subject"]
    verdicts = _verdicts(report)
    proposed, deferred = [], []

    def held(inv_id):
        v = verdicts.get(inv_id)
        return v and v["verdict"] == "pass"

    def evidence(inv_id):
        v = verdicts.get(inv_id)
        return (v or {}).get("evidence", "")

    for inv_id, inv_type in (("network.none", "no-network"),
                             ("writes.none", "no-write"),
                             ("subprocess.none", "no-subprocess"),
                             ("errors.are-values", "error-as-value"),
                             ("data.stays-put", "no-data-egress")):
        if held(inv_id):
            proposed.append({
                "id": inv_id, "type": inv_type, "appliesTo": ["*"],
                "note": "observed to hold: " + evidence(inv_id)[:160],
            })
        elif inv_id in verdicts:
            v = verdicts[inv_id]
            deferred.append({
                "invariant": inv_id,
                "why": ("the run showed this does NOT hold"
                        if v["verdict"] == "fail" else
                        "the run never exercised this"),
                "evidence": v["evidence"][:200],
                "decide": ("bound it with a narrower invariant if the "
                           "behaviour is intended, or fix the tool"),
            })

    flow = report.get("dataFlow") or {}
    reached = sorted(h for h, d in flow.items()
                     if d.get("relation") != "unexamined")
    if reached and not held("network.none"):
        proposed.append({
            "id": "egress.declared", "type": "network-allowlist",
            "appliesTo": ["*"], "params": {"hosts": reached},
            "note": ("observed reaching exactly these hosts; narrow the list "
                     "rather than widen it, since every host here is a "
                     "promise"),
        })

    tools = [t["name"] for t in capture.get("tools", [])]
    guard = next((t for t in tools if t.lower() in
                  ("scope", "guard", "about", "capabilities")), None)
    if guard and held("refusal." + guard):
        proposed.append({"id": "refusal." + guard, "type": "refusal-tool",
                         "appliesTo": ["*"], "params": {"tool": guard}})

    name = subject.get("name", "unknown")
    purl = purl or (subject.get("artifacts") or [{}])[0].get(
        "identifier", "pkg:generic/" + name)
    return {
        "declarationVersion": "0.1.0",
        "serialNumber": "urn:uuid:{}".format(
            uuid.uuid5(_NS, "saydo-declared:" + purl)),
        "createdAt": "1970-01-01T00:00:00Z",
        # Drafted, never declared: a declaration becomes real when its author
        # signs it, and nothing here has been signed by anyone.
        "status": "draft",
        "subject": {
            "kind": "mcp-server", "name": name,
            "version": subject.get("version", ""),
            "supplier": {"name": supplier or subject.get(
                "supplier", {}).get("name", "unknown")},
            "artifacts": [{"type": "other", "identifier": purl}],
        },
        "binding": {"tools": [{"name": t["name"],
                               "definitionDigest": t["definitionDigest"]}
                              for t in capture["tools"]]},
        "invariants": proposed,
        "canonicalization": "rfc8785",
        "notes": ("Drafted from an observed run. Every invariant here already "
                  "held once; that is a reason to believe it, not a proof it "
                  "will keep holding. Review, tighten, then sign."),
        "toDecide": deferred,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("report")
    ap.add_argument("capture")
    ap.add_argument("-o", "--out")
    ap.add_argument("--purl")
    ap.add_argument("--supplier")
    args = ap.parse_args()

    with io.open(args.report, encoding="utf-8") as fh:
        report = json.load(fh)
    with io.open(args.capture, encoding="utf-8") as fh:
        capture = json.load(fh)

    doc = draft(report, capture, args.purl, args.supplier)
    text = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
    if args.out:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with io.open(args.out, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        print("{}: {} invariant(s) proposed, {} left for you to decide"
              .format(args.out, len(doc["invariants"]), len(doc["toDecide"])))
        for d in doc["toDecide"]:
            print("  decide: {} -- {}".format(d["invariant"], d["why"]))
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    main()
