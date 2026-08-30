"""The registry: what SayDo currently says about a tool, and for how long.

The first three layers produce a receipt. A receipt is a fact about one run at
one moment, and left there it answers the wrong question. Nobody choosing a
tool wants to know that it behaved in August; they want to know whether it is
behaving now, and to find that out without asking its author.

So the registry adds two things a receipt cannot carry on its own.

EXPIRY. A conformance claim is perishable. Software changes, and a receipt
older than its subject's current release says nothing about what is installed
today. Entries therefore expire, and an expired entry reads as unknown rather
than as the last thing that happened to be true -- the failure mode being a
badge that stays green for two years because nobody re-ran anything.

REVOCATION. Sometimes what was true stops being true and someone needs to say
so loudly and immediately, without waiting for expiry. A revoked entry is
never silently deleted: the reason stays on the record, because a tool that
was revoked and then quietly disappeared from the registry is exactly the
history a buyer needs and a vendor would prefer to lose.

The registry stores no secret and grants no authority. It is an index of
receipts, and every claim in it points at a receipt anyone can verify without
the registry, the author, or us. If this index vanished tomorrow, every
receipt it names would still be checkable -- which is the property that keeps
it from becoming something people have to trust.
"""

from __future__ import annotations

import argparse
import datetime
import io
import json
import os

#: Long enough to be useful, short enough that a stale claim stops being
#: quoted as a current one.
DEFAULT_TTL_DAYS = 30

UNKNOWN = "unknown"
WARRANTED = "warranted"
FAILING = "failing"
EXPIRED = "expired"
REVOKED = "revoked"
#: Nothing failed and nothing was shown. Kept distinct from WARRANTED because
#: collapsing them is how a registry ends up publishing a green mark for a
#: server that declined every call it was given.
INCONCLUSIVE = "inconclusive"


def _now(at=None):
    if at:
        return datetime.datetime.fromisoformat(at.replace("Z", "+00:00"))
    return datetime.datetime.now(datetime.timezone.utc)


def load(path):
    if not os.path.exists(path):
        return {"registryVersion": "0.1.0", "entries": {}}
    with io.open(path, encoding="utf-8") as fh:
        return json.load(fh)


def save(path, registry):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with io.open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(registry, fh, indent=2, ensure_ascii=False, sort_keys=True)
        fh.write("\n")


def publish(registry, anchor, receipt_rows, at=None, ttl_days=DEFAULT_TTL_DAYS):
    """Record what a receipt establishes, and when that stops being current."""
    opening = next((r for r in receipt_rows if r.get("type") == "receipt-open"),
                   {})
    closing = next((r for r in receipt_rows if r.get("type") == "receipt-close"),
                   {})
    subject = opening.get("subject", {})
    key = subject.get("purl") or subject.get("name")
    if not key:
        raise ValueError("a receipt with no subject cannot be published")

    now = _now(at)
    entry = registry["entries"].get(key, {})
    if entry.get("state") == REVOKED:
        # A revocation is not undone by publishing a newer receipt. Someone
        # decided this tool should not be relied on; only an explicit
        # reinstatement reverses that, and the history stays either way.
        entry.setdefault("supersededAttempts", []).append({
            "head": anchor.get("head"), "at": now.isoformat()})
        registry["entries"][key] = entry
        return entry

    signed = bool(anchor.get("signature"))
    conformant = bool(closing.get("conformant"))
    # A pass on the refusal tool is the server answering a question about
    # itself, not conduct. A warrant may not rest on it.
    established = [r for r in receipt_rows
                   if r.get("type") == "verdict" and r.get("verdict") == "pass"
                   and r.get("invariantType") != "refusal-tool"]
    if not conformant:
        state = FAILING
    elif not established:
        state = INCONCLUSIVE
    elif not signed:
        state = "draft"
    else:
        state = WARRANTED

    entry = {
        "subject": subject,
        "state": state,
        "receipt": {
            "head": anchor.get("head"),
            "priorReceipt": anchor.get("priorReceipt"),
            "genesis": anchor.get("genesis"),
        },
        "signature": ({"keyId": anchor["signature"].get("keyId"),
                       "signer": anchor["signature"].get("signer")}
                      if signed else None),
        "enforcement": opening.get("harness", {}).get("enforcement",
                                                      "observed"),
        "publishedAt": now.isoformat(),
        "expiresAt": (now + datetime.timedelta(days=ttl_days)).isoformat(),
        "drift": [
            {"kind": r["kind"], "subject": r["subject"],
             "severity": r["severity"]}
            for r in receipt_rows if r.get("type") == "drift"
        ],
        "history": entry.get("history", []),
    }
    if entry["receipt"]["priorReceipt"]:
        entry["history"] = ([entry["receipt"]["priorReceipt"]]
                            + entry["history"])[:20]
    registry["entries"][key] = entry
    return entry


def revoke(registry, key, reason, at=None):
    """Withdraw a claim, keeping the reason on the record."""
    entry = registry["entries"].get(key)
    if not entry:
        raise KeyError(key)
    entry["state"] = REVOKED
    entry["revokedAt"] = _now(at).isoformat()
    entry["revocationReason"] = reason
    return entry


def lookup(registry, key, at=None):
    """What the registry says about a tool right now.

    Expiry is applied at read time rather than by a sweep, so a claim cannot
    stay green merely because nothing has run recently to retire it.
    """
    entry = registry["entries"].get(key)
    if not entry:
        return {"state": UNKNOWN, "key": key,
                "advice": "no receipt on record; treat as unverified"}

    out = dict(entry)
    out["key"] = key
    if entry["state"] == REVOKED:
        out["advice"] = ("withdrawn: " + entry.get("revocationReason", "")
                         + " -- do not rely on any earlier claim")
        return out

    expires = datetime.datetime.fromisoformat(entry["expiresAt"])
    if _now(at) > expires:
        out["state"] = EXPIRED
        out["advice"] = ("the last conformance run is too old to describe what "
                         "is installed today; re-verify before relying on it")
        return out

    if entry["state"] == WARRANTED:
        serious = [d for d in entry.get("drift", [])
                   if d["severity"] == "serious"]
        out["advice"] = ("conformed to its declaration when last checked"
                         + (", but {} serious change(s) were recorded since "
                            "the previous run".format(len(serious))
                            if serious else ""))
    elif entry["state"] == FAILING:
        out["advice"] = "did not conform to its declaration when last checked"
    elif entry["state"] == INCONCLUSIVE:
        out["advice"] = ("the last run established nothing: the tool did no "
                         "observable work, so it has not been shown to be "
                         "well behaved, only unobserved")
    else:
        out["advice"] = ("tested but unsigned, so nobody has put their name "
                         "to it")
    return out


def badge(entry):
    """The one line a trust mark may honestly show.

    Never a bare grade. A mark that says only "verified" invites the reader to
    supply their own meaning, which is how a badge becomes a lie nobody
    technically told.
    """
    state = entry.get("state", UNKNOWN)
    text = {
        WARRANTED: "conformed when last checked",
        FAILING: "did NOT conform when last checked",
        INCONCLUSIVE: "checked, but nothing was established",
        EXPIRED: "claim expired, re-verification needed",
        REVOKED: "withdrawn",
        UNKNOWN: "not on record",
        "draft": "tested, unsigned",
    }.get(state, state)
    return {"state": state, "label": "SayDo: " + text,
            "receipt": (entry.get("receipt") or {}).get("head"),
            "meaning": ("this links to the receipt behind it; a badge without "
                        "its evidence is decoration")}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("registry")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("publish")
    p.add_argument("anchor")
    p.add_argument("--at")
    p.add_argument("--ttl-days", type=int, default=DEFAULT_TTL_DAYS)

    r = sub.add_parser("revoke")
    r.add_argument("key")
    r.add_argument("reason")
    r.add_argument("--at")

    q = sub.add_parser("lookup")
    q.add_argument("key")
    q.add_argument("--at")

    ls = sub.add_parser("list")
    ls.add_argument("--at")

    args = ap.parse_args()
    registry = load(args.registry)

    if args.cmd == "publish":
        with io.open(args.anchor, encoding="utf-8") as fh:
            anchor = json.load(fh)
        ledger = args.anchor.replace(".anchor.json", ".receipt.jsonl")
        rows = [json.loads(l) for l in io.open(ledger, encoding="utf-8")
                if l.strip()]
        entry = publish(registry, anchor, rows, args.at, args.ttl_days)
        save(args.registry, registry)
        print("published {}: {} (expires {})".format(
            entry["subject"].get("purl"), entry["state"],
            entry["expiresAt"][:10]))
    elif args.cmd == "revoke":
        revoke(registry, args.key, args.reason, args.at)
        save(args.registry, registry)
        print("revoked {}: {}".format(args.key, args.reason))
    elif args.cmd == "lookup":
        print(json.dumps(lookup(registry, args.key, args.at), indent=2))
    else:
        for key in sorted(registry["entries"]):
            e = lookup(registry, key, args.at)
            print("  {:<44} {:<10} {}".format(key[:44], e["state"],
                                              e["advice"][:60]))


if __name__ == "__main__":
    main()
