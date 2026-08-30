"""Compare a tool against what it was last time, and say what changed.

"Continuous conformance" has meant, so far, running the check more than once.
That is not the same thing. The interesting event is never a single verdict --
it is a tool that passed last week and does not this week, or one whose
description is unchanged while its behaviour is not. A capability rug-pull
looks exactly like normal operation in any single run; it only exists as a
difference between two.

So a receipt is compared with its predecessor, and the differences are
themselves findings:

    definition-drift  the tool's declared surface changed. Same name, same
                      version, different digest: the description a model
                      reads was rewritten under it.
    surface-drift     tools appeared or disappeared.
    behaviour-drift   an invariant that held now fails, or vice versa.
    destination-drift the tool started, or stopped, sending data somewhere.

The receipts already chain within a run. Naming the prior head in each new
receipt chains them ACROSS runs, so a history cannot be quietly rewritten:
dropping an inconvenient week breaks the link, and the break is visible to
anyone who kept an older copy.
"""

from __future__ import annotations

import io
import json
import os


def load_receipt(path):
    """Rows of a receipt, or None if it is not there."""
    if not os.path.exists(path):
        return None
    rows = []
    with io.open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    pass
    return rows or None


def _row(rows, kind):
    return next((r for r in rows if r.get("type") == kind), {})


def _verdicts(rows):
    return {r["invariant"]: r for r in rows if r.get("type") == "verdict"}


def _tools(rows):
    return {t["name"]: t.get("definitionDigest")
            for t in _row(rows, "capture").get("tools", [])}


def compare(previous, current):
    """Findings about what changed between two receipts of the same subject."""
    if not previous:
        return []

    findings = []
    old_open, new_open = _row(previous, "receipt-open"), _row(current, "receipt-open")
    old_subject = old_open.get("subject", {})
    new_subject = new_open.get("subject", {})
    same_version = old_subject.get("version") == new_subject.get("version")

    old_tools, new_tools = _tools(previous), _tools(current)

    for name in sorted(set(new_tools) - set(old_tools)):
        findings.append({
            "kind": "surface-drift", "tool": name,
            "detail": "a tool that did not exist in the previous receipt",
            "severity": "notable" if same_version else "expected",
        })
    for name in sorted(set(old_tools) - set(new_tools)):
        findings.append({
            "kind": "surface-drift", "tool": name,
            "detail": "a tool present in the previous receipt is gone",
            "severity": "notable" if same_version else "expected",
        })
    for name in sorted(set(old_tools) & set(new_tools)):
        if old_tools[name] != new_tools[name]:
            findings.append({
                "kind": "definition-drift", "tool": name,
                "detail": ("the tool's name, description or input schema "
                           "changed: {} -> {}".format(
                               (old_tools[name] or "?")[:23],
                               (new_tools[name] or "?")[:23])),
                # Redefining a tool without changing the version is the shape
                # of a rug-pull: the text a model reads to decide whether to
                # trust the tool was rewritten under an identifier that says
                # nothing moved.
                "severity": "serious" if same_version else "notable",
            })

    old_v, new_v = _verdicts(previous), _verdicts(current)
    for inv in sorted(set(old_v) & set(new_v)):
        before, after = old_v[inv]["verdict"], new_v[inv]["verdict"]
        if before == after:
            continue
        if before == "pass" and after == "fail":
            sev = "serious"
            detail = "held before and is refuted now: " + new_v[inv]["evidence"][:120]
        elif before == "fail" and after == "pass":
            sev = "improvement"
            detail = "was refuted before and holds now"
        else:
            sev = "notable"
            detail = "{} -> {}".format(before, after)
        findings.append({"kind": "behaviour-drift", "tool": inv,
                         "detail": detail, "severity": sev})

    findings += _destination_drift(previous, current)
    return findings


def _destination_drift(previous, current):
    """Where the tool sends data, then and now."""
    def destinations(rows):
        out = {}
        for r in rows:
            if r.get("type") != "verdict":
                continue
            flow = r.get("dataFlow") or {}
            for host, v in flow.items():
                out[host] = v.get("relation")
        return out

    old, new = destinations(previous), destinations(current)
    findings = []
    for host in sorted(set(new) - set(old)):
        findings.append({
            "kind": "destination-drift", "tool": host,
            "detail": "a destination that did not appear before ({})".format(
                new[host]),
            "severity": "serious" if new[host] == "input-dependent" else "notable",
        })
    for host in sorted(set(old) & set(new)):
        if old[host] != new[host] and new[host] == "input-dependent":
            findings.append({
                "kind": "destination-drift", "tool": host,
                "detail": ("this destination did not carry the tool's input "
                           "before and does now ({} -> {})".format(
                               old[host], new[host])),
                "severity": "serious",
            })
    return findings


def summarise(findings):
    if not findings:
        return ["nothing changed since the previous receipt"]
    order = {"serious": 0, "notable": 1, "improvement": 2, "expected": 3}
    rows = sorted(findings, key=lambda f: order.get(f["severity"], 9))
    return ["[{}] {} {}: {}".format(f["severity"], f["kind"], f["tool"],
                                    f["detail"])
            for f in rows]
