"""Join what a server SAYS IT IS to what it was OBSERVED doing.

A sweep on its own produces a number with no scale: "156 servers sent their
input somewhere" invites the reader to supply their own denominator, and every
reader supplies a different one. The same measurement inside a category is a
claim someone can act on -- if you are choosing a server to hold your bank
credentials, the rate among servers that handle money is the number you want,
and it is not the rate across everything.

Nothing here re-measures anything. The behaviour is whatever the sweep already
observed; this only sorts it and keeps the arithmetic honest.

Three denominators, never mixed:

    discovered   in this category, from its own description
    exercised    started, listed tools, and could be driven
    established  the harness demonstrated at least one thing about its conduct

Rates are quoted over `established`, the smallest and only honest one. A server
that would not start without a credential has not been shown to be safe; a
server that started and then declined every call has not been shown anything
either. Counting either as clean would turn "we never got it to act" into a
clean bill of health for a whole category, which is the exact error that makes
security surveys worthless.

A category with too few established servers gets no rate at all. Three out of
four is not 75% of anything, and printing it as a percentage would give a
number about three servers the authority of a number about a population.
"""

from __future__ import annotations

import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import categories as categories_mod

#: Below this many established servers a category gets counts only, no rate.
#: A percentage computed over four servers reads as a fact about a population
#: and is a fact about four servers.
RATE_FLOOR = 10


def load_results(path):
    """Accept a batch folder or a single results file; both appear in CI."""
    if os.path.isdir(path):
        results = []
        for name in sorted(os.listdir(path)):
            if not name.endswith(".json"):
                continue
            with io.open(os.path.join(path, name), encoding="utf-8") as fh:
                try:
                    results.extend(json.load(fh).get("results", []))
                except ValueError:
                    continue
        return results
    with io.open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return data.get("results", data) if isinstance(data, dict) else data


def _carries_input(record):
    flow = record.get("dataFlow") or {}
    return sorted(host for host, v in flow.items()
                  if v.get("relation") in ("input-dependent",
                                           "retained-across-runs"))


def _unexamined(record):
    flow = record.get("dataFlow") or {}
    return sorted(host for host, v in flow.items()
                  if v.get("relation") == "unexamined")


def join(results):
    """Per-category behaviour, plus what the run could not speak to."""
    buckets, carried_claims = {}, 0
    for record in results:
        hits = categories_mod.classify(record)
        if not hits:
            continue
        # A record predating the claim check carries no `claimContradictions`
        # key at all, which is different from carrying an empty one. Counting
        # the first as "no contradictions" would report the age of the sweep
        # as a property of the servers in it.
        knows_claims = "claimContradictions" in record
        if knows_claims:
            carried_claims += 1
        for hit in hits:
            bucket = buckets.setdefault(hit["category"], {
                "category": hit["category"],
                "sensitive": hit["sensitive"],
                "discovered": 0, "exercised": 0, "established": 0,
                "carries": [], "unexamined": [], "silent": 0,
                "contradicted": [], "claimsKnownFor": 0})
            bucket["discovered"] += 1
            if record.get("outcome") != "measured":
                continue
            bucket["exercised"] += 1
            if knows_claims:
                bucket["claimsKnownFor"] += 1
                for conflict in record.get("claimContradictions") or []:
                    bucket["contradicted"].append({
                        "name": record.get("name"),
                        "promise": conflict.get("claim"),
                        "quote": conflict.get("quote"),
                        "observed": conflict.get("observed")})
            if not (record.get("established") or 0):
                bucket["silent"] += 1
                continue
            bucket["established"] += 1
            carries = _carries_input(record)
            if carries:
                bucket["carries"].append({"name": record.get("name"),
                                          "hosts": carries})
            elif _unexamined(record):
                bucket["unexamined"].append({"name": record.get("name"),
                                             "hosts": _unexamined(record)})
    return {"categories": sorted(buckets.values(),
                                 key=lambda b: (not b["sensitive"],
                                                -b["established"])),
            "recordsCarryingClaims": carried_claims,
            "records": len(results)}


def _rate(numerator, denominator):
    if denominator < RATE_FLOOR:
        return "--"
    return "{:.0f}%".format(100.0 * numerator / denominator)


def render(joined):
    L = []
    W = L.append
    W("category         disc   exer   estab   carry   rate   promise-broken")
    W("-" * 70)
    for b in joined["categories"]:
        mark = "*" if b["sensitive"] else " "
        W("{}{:<14} {:>5} {:>6} {:>7} {:>7} {:>6}   {}".format(
            mark, b["category"], b["discovered"], b["exercised"],
            b["established"], len(b["carries"]),
            _rate(len(b["carries"]), b["established"]),
            # SERVERS with a broken promise, not promises broken. One server
            # that makes four promises and breaks all four is one finding
            # about one project; counting four would let a single verbose
            # description move a whole category's number.
            len({c["name"] for c in b["contradicted"]})
            if b["claimsKnownFor"] else "n/a"))
    W("")
    W("disc  = in this category, from the server's own description")
    W("exer  = started and could be driven")
    W("estab = the harness demonstrated something about its conduct")
    W("carry = sent the tool's own input to a host (counterfactual-confirmed)")
    W("rate  = carry over estab; '--' where estab < {} -- too few to be a rate"
      .format(RATE_FLOOR))
    W("promise-broken = SERVERS contradicting a promise of their own, not "
      "promises broken")
    W("* = holds something worth losing")
    W("")

    if joined["recordsCarryingClaims"] < joined["records"]:
        W("promise-broken is 'n/a' for {} of {} records: they were swept "
          "before the claim check existed and carry no claim data. That is "
          "not zero contradictions, it is no measurement -- reporting it as "
          "zero would publish the age of the sweep as a property of those "
          "servers.".format(joined["records"] - joined["recordsCarryingClaims"],
                            joined["records"]))
        W("")

    shown = False
    for b in joined["categories"]:
        if not b["contradicted"]:
            continue
        if not shown:
            W("Servers whose observed behaviour contradicts their own stated")
            W("promises, quoted from the instructions they hand a client:")
            W("")
            shown = True
        W("[{}]".format(b["category"]))
        for c in b["contradicted"]:
            W("  {}".format(c["name"]))
            W("    promised : {}".format(c["promise"]))
            W("    said     : \"{}\"".format((c["quote"] or "")[:150]))
            W("    observed : {}".format(c["observed"]))
        W("")
    return "\n".join(L)


def check():
    """Pin the three ways this join misreported, all found end to end.

    Each was invisible to the unit tests: the rules were right, the claim
    check was right, and the table built from both was still wrong. They are
    listed here because every one of them makes a category look worse or
    better than it is, which is the only kind of bug that matters in a report
    naming real projects.
    """
    problems = []

    contradiction = {"kind": "claim-contradicted",
                     "claim": "that it runs offline",
                     "quote": "Runs entirely offline.",
                     "observed": "egress: sync->example.com"}
    # The description must actually classify, or this tests nothing. It said
    # "a notes server" at first, which matches no rule, and the check crashed
    # on an empty category list rather than reporting that its own fixture had
    # fallen out of scope.
    describes = "A local-only notes server with calendar and contacts"
    verbose = {"name": "verbose", "description": describes,
               "outcome": "measured", "established": 1, "dataFlow": {},
               "claimContradictions": [contradiction,
                                       dict(contradiction,
                                            claim="that it is local-only")]}
    quiet = {"name": "quiet", "description": describes,
             "outcome": "measured", "established": 1, "dataFlow": {},
             "claimContradictions": []}
    joined = join([verbose, quiet])
    if not joined["categories"]:
        return ["the fixture used to test the join no longer matches any "
                "category, so the join is not being tested at all"]
    bucket = joined["categories"][0]

    # 1. The promise must survive into the report. Reading the wrong key
    #    printed "promised : None" under a real server's name -- an accusation
    #    with the substance removed and the name left in.
    if any(c["promise"] is None for c in bucket["contradicted"]):
        problems.append("a contradiction reached the report without the "
                        "promise it contradicts")

    # 2. One server breaking four promises is one finding about one project.
    servers = len({c["name"] for c in bucket["contradicted"]})
    if servers != 1:
        problems.append("counted {} servers with broken promises where one "
                        "server broke two".format(servers))

    # 3. No claim data is not zero contradictions.
    old = join([{"name": "old", "description": describes,
                 "outcome": "measured", "established": 1, "dataFlow": {}}])
    if old["categories"] and old["categories"][0]["claimsKnownFor"] != 0:
        problems.append("a record carrying no claim data was treated as "
                        "having been checked and found clean")

    # 4. A rate over a handful of servers reads as a fact about a population.
    if _rate(3, 4) != "--":
        problems.append("printed a percentage over fewer than {} servers"
                        .format(RATE_FLOOR))
    return problems


def main():
    argv = sys.argv[1:]
    if argv and argv[0] == "--check":
        problems = check()
        for problem in problems:
            print("  " + problem)
        raise SystemExit(1 if problems else 0)
    if not argv:
        raise SystemExit(__doc__)
    results = load_results(argv[0])
    joined = join(results)
    text = render(joined)
    print(text)
    if len(argv) > 1:
        with io.open(argv[1], "w", encoding="utf-8", newline="\n") as fh:
            json.dump(joined, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        print("\nwrote {}".format(argv[1]))


if __name__ == "__main__":
    main()
