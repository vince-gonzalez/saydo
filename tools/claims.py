"""What a server says about itself, in a form the harness can contradict.

Every other check here compares behaviour to a declaration the author wrote
FOR SayDo. Almost nobody has written one. But almost every server ships prose
that makes the same promises in marketing form -- "runs entirely locally",
"no telemetry", "your data never leaves your machine" -- in its README, its
package description and the instructions it hands the model on connect.

Those are claims. They can be read, and they can be contradicted by the same
run that produces every other verdict. That turns a corpus sweep from "these
servers make network calls", which is nearly a tautology, into "this server
says it makes none, and made three", which is a finding.

THE RULES THIS LIVES BY
-----------------------
Only the server's OWN words are used, and the exact phrase is quoted, so a
reader can check the reading rather than trust it.

Only a DIRECT contradiction is reported: a claim of no network against
observed network, a claim of read-only against an observed write. Nothing is
inferred about intent, and no claim is invented on the author's behalf.

A claim with no matching observation produces NOTHING -- not a pass. If the
run never established whether the tool reaches the network, a promise that it
does not is neither kept nor broken, and saying otherwise would be the
silence-as-evidence error this project exists to refuse.
"""

from __future__ import annotations

import re

#: (expectation, pattern, meaning, strength). Strength is the whole fairness
#: mechanism. "local-only" and "no telemetry" are promises. "runs locally" is
#: not: "runs locally for development, then deploys to the cloud" says nothing
#: about runtime egress, and reading it as a promise would put an accusation
#: on a real project over an ambiguous phrase. Only EXPLICIT claims are ever
#: contradicted; suggestive ones are surfaced for a person to judge.
CLAIM_PATTERNS = [
    # "offline" and "locally" are not the same promise. Offline says it does
    # not use the network. Locally says where the process runs, which is true
    # of every stdio MCP server ever written and of plenty that call APIs all
    # day. Splitting them is the difference between a finding and a libel.
    ("no-network", r"\b(?:runs?|works?|operates?)\s+(?:entirely\s+|fully\s+|"
                   r"completely\s+)?offline\b",
     "that it runs offline", "explicit"),
    ("no-network", r"\b(?:runs?|works?|operates?)\s+(?:entirely\s+|fully\s+|"
                   r"completely\s+)?(?:locally|on[- ]device)\b",
     "that it runs locally", "suggestive"),
    ("no-network", r"\b(?:no|zero|without)\s+(?:any\s+)?"
                   r"(?:network|internet|external|outbound)\s+"
                   r"(?:access|calls?|requests?|connections?|traffic)\b",
     "that it makes no network calls", "explicit"),
    ("no-network", r"\b(?:100%\s+)?(?:fully\s+)?local[- ]only\b",
     "that it is local-only", "explicit"),
    ("no-network", r"\b(?:never|does\s+not|doesn't)\s+(?:connect|phone|reach)\s+"
                   r"(?:out|home|to\s+the\s+internet)\b",
     "that it never connects out", "explicit"),
    ("no-data-egress", r"\b(?:your|user)\s+data\s+(?:never|does\s+not|doesn't)\s+"
                       r"leaves?\b",
     "that your data never leaves", "explicit"),
    ("no-data-egress", r"\b(?:no|zero|without)\s+(?:telemetry|tracking|"
                       r"analytics|data\s+collection)\b",
     "that it collects no telemetry", "explicit"),
    ("no-data-egress", r"\b(?:nothing|no\s+data)\s+is\s+(?:sent|uploaded|"
                       r"transmitted|shared)\b",
     "that it sends nothing", "explicit"),
    ("no-data-egress", r"\b(?:stays?|remains?)\s+on\s+your\s+(?:machine|device|"
                       r"computer)\b",
     "that data stays on your machine", "explicit"),
    ("no-write", r"\bread[- ]only\b", "that it is read-only", "explicit"),
    ("no-write", r"\b(?:never|does\s+not|doesn't)\s+(?:modify|write|alter|"
                 r"change)\s+(?:any\s+)?(?:files?|your\s+\w+)\b",
     "that it modifies nothing", "explicit"),
    ("no-write", r"\bnon[- ]destructive\b", "that it is non-destructive", "explicit"),
    ("no-subprocess", r"\b(?:no|without)\s+(?:shell|subprocess|child\s+process|"
                      r"command\s+execution)\b",
     "that it starts no other programs", "explicit"),
]

_COMPILED = [(kind, re.compile(pattern, re.I), meaning, strength)
             for kind, pattern, meaning, strength in CLAIM_PATTERNS]

#: Words that turn a claim about running into a claim about DEVELOPMENT. A
#: phrase qualified by these promises nothing about what the shipped tool does
#: at runtime, and treating it as a promise manufactures a contradiction.
_QUALIFIERS = re.compile(
    r"(?:for|during|in|while)\s+(?:local\s+)?(?:development|dev|testing|"
    r"tests?|debugging|CI)|development\s+(?:mode|only|server)", re.I)

#: Which verdict id contradicts which claim. A claim is only ever tested
#: against a verdict that actually ran.
CONTRADICTED_BY = {
    "no-network": ("network.none", "no-network"),
    "no-data-egress": ("data.stays-put", "no-data-egress"),
    "no-write": ("writes.none", "no-write"),
    "no-subprocess": ("subprocess.none", "no-subprocess"),
}


def extract(*texts):
    """Every promise found in the server's own prose. [] when it makes none."""
    claims, seen = [], set()
    for text in texts:
        if not text:
            continue
        flat = re.sub(r"\s+", " ", str(text))
        for kind, pattern, meaning, strength in _COMPILED:
            match = pattern.search(flat)
            if not match or (kind, meaning) in seen:
                continue
            seen.add((kind, meaning))
            start = max(0, match.start() - 50)
            end = min(len(flat), match.end() + 50)
            window = flat[max(0, match.start() - 80):match.end() + 80]
            strength_here = strength
            if _QUALIFIERS.search(window):
                # "runs locally for development" is not a runtime promise.
                strength_here = "qualified"
            claims.append({
                "expectation": kind,
                "meaning": meaning,
                "strength": strength_here,
                # Their words, quoted, so the reading can be checked rather
                # than taken on trust.
                "quote": (("…" if start else "") + flat[start:end].strip()
                          + ("…" if end < len(flat) else "")),
            })
    return claims


def contradictions(claims, verdicts, strengths=("explicit",)):
    """Where the server's own words disagree with what the run observed.

    `verdicts` is the report's list. Only a verdict that FAILED contradicts a
    claim; not-covered means the question was never settled, and an unsettled
    question refutes nothing.
    """
    by_id = {v.get("id"): v for v in (verdicts or [])}
    by_type = {}
    for v in (verdicts or []):
        by_type.setdefault(v.get("type"), v)

    found = []
    for claim in claims:
        if claim.get("strength", "explicit") not in strengths:
            # Suggestive or development-qualified wording is reported by
            # extract() and never contradicted. An ambiguous phrase is not
            # evidence of a broken promise, and this names real projects.
            continue
        target = CONTRADICTED_BY.get(claim["expectation"])
        if not target:
            continue
        verdict = by_id.get(target[0]) or by_type.get(target[1])
        if not verdict or verdict.get("verdict") != "fail":
            continue
        found.append({
            "kind": "claim-contradicted",
            "claim": claim["meaning"],
            "quote": claim["quote"],
            "invariant": verdict.get("id"),
            "observed": (verdict.get("evidence") or "")[:300],
            "note": "the server's own description makes this promise and the "
                    "run observed the opposite. This compares its words to its "
                    "behaviour; it says nothing about why.",
        })
    return found
