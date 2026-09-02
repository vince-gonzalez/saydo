"""A control group for the install-hook rate, or the finding means nothing.

"67 of 1,641 MCP packages can run code on npm install" is 4.1%, and 4.1% is
only a finding if npm at large is lower. If ordinary packages sit at the same
rate then nothing about MCP was measured -- npm's baseline was measured and an
MCP label put on it. A number with no comparison is not evidence, and the
comparison is cheap, so there is no excuse for quoting the first without it.

SAMPLING, AND ITS BIAS, STATED. There is no public uniform-random sample of
npm. This walks the registry's own search endpoint across neutral, unrelated
keywords at varied offsets, which yields packages of roughly comparable
discoverability to the MCP corpus -- itself gathered by search. A matched-
visibility comparison, not a random one. Both populations carry the same bias,
which is the property that makes them comparable at all.

Two defects this file shipped with, both found by writing its self-test:

  The treatment numbers were HARDCODED into the report. The control was
  measured live and compared against constants typed into the source, so a
  corpus re-run would have silently compared today's control against
  yesterday's treatment. They are read from the survey file now.

  A short sample was SILENT. Asked for 1,200 it returned 576, because the
  keyword-by-offset space ran out, and it said nothing. The shortfall was
  caught by eye, which is not a method. It is reported now.
"""

from __future__ import annotations

import io
import json
import math
import os
import random
import sys
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import install_scripts

#: Deliberately mundane and unrelated to agents, protocols or model tooling. A
#: control drawn from "ai" or "server" keywords would re-sample the same
#: neighbourhood the treatment came from.
KEYWORDS = ("csv", "colour", "date", "regex", "markdown", "image", "queue",
            "cache", "logger", "router", "parser", "template", "validation",
            "geometry", "audio", "pdf", "spreadsheet", "compression",
            "unicode", "random", "matrix", "calendar", "currency", "diff")

#: A name containing any of these is not admissible as a control, because a
#: control containing the treatment cannot measure a difference.
EXCLUDE = ("mcp", "model-context", "modelcontext", "anthropic", "claude",
           "openai", "llm", "agent")

OFFSETS = (0, 20, 40, 60, 80, 100, 120, 140)


def _admissible(name, seen):
    """Whether this name may enter the control.

    Split out so it can be tested without the network. This filter decides
    whether the comparison means anything at all, and it was previously
    exercised only by a live run.
    """
    if not name or name in seen:
        return False
    low = name.lower()
    return not any(bad in low for bad in EXCLUDE)


def search(term, offset, size=20, timeout=25):
    url = ("https://registry.npmjs.org/-/v1/search?text={}&size={}&from={}"
           .format(urllib.parse.quote(term), size, offset))
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "saydo/0.1"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
    except Exception:
        return []
    return [o.get("package", {}).get("name", "")
            for o in data.get("objects", [])]


def sample(target, seed=20260902, fetch=None):
    """Return (names, shortfall).

    `fetch` is injectable so ordering, filtering and exhaustion can be tested
    without touching the registry.
    """
    fetch = fetch or search
    rng = random.Random(seed)
    names, seen = [], set()
    terms = list(KEYWORDS)
    rng.shuffle(terms)
    for term in terms:
        for offset in OFFSETS:
            if len(names) >= target:
                return names, 0
            for name in fetch(term, offset):
                if not _admissible(name, seen):
                    continue
                seen.add(name)
                names.append(name)
    return names, max(0, target - len(names))


def treatment(path=None):
    """The MCP numbers, read rather than remembered."""
    path = path or os.path.join(os.path.dirname(HERE), "corpus",
                                "install-hooks-full.json")
    with io.open(path, encoding="utf-8") as fh:
        rows = json.load(fh)["rows"]
    answered = [r for r in rows if r["status"] != "unknown"]
    hooked = [r for r in answered if r["status"] == "hooks"]
    native = [r for r in hooked if all(h["ordinary"] for h in r["hooks"])]
    return len(hooked), len(answered), len(native)


def wilson(k, n, z=1.96):
    if not n:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (100 * (centre - half), 100 * (centre + half))


def compare(k1, n1, k2, n2):
    """Two-proportion z-test. Returns (ratio, z, p, intervals_overlap)."""
    if not n1 or not n2 or not (k1 + k2):
        return (0.0, 0.0, 1.0, True)
    p1, p2 = k1 / n1, k2 / n2
    pooled = (k1 + k2) / (n1 + n2)
    se = math.sqrt(pooled * (1 - pooled) * (1 / n1 + 1 / n2))
    z = (p1 - p2) / se if se else 0.0
    pval = math.erfc(abs(z) / math.sqrt(2))
    lo1, hi1 = wilson(k1, n1)
    lo2, hi2 = wilson(k2, n2)
    overlap = not (lo1 > hi2 or lo2 > hi1)
    ratio = (p1 / p2) if p2 else float("inf")
    return (ratio, z, pval, overlap)


def check():
    """Problems with this sampler. [] = good.

    No network. A self-test that needs the registry is one that gets skipped
    on a bad day, and the parts worth testing -- what is admitted, what is
    deduped, whether a short sample is reported, whether the treatment is read
    or remembered, whether the arithmetic is right -- do not need it.
    """
    problems = []

    # 1. The control must not contain the treatment.
    for name in ("some-mcp-server", "@scope/MCP-thing", "openai-helper",
                 "my-llm-agent", "model-context-tool"):
        if _admissible(name, set()):
            problems.append(
                "{!r} was admitted into the control; a control containing the "
                "treatment cannot measure a difference".format(name))

    # 2. Ordinary packages must still get in, or the control is empty.
    for name in ("left-pad", "csv-parse", "date-fns"):
        if not _admissible(name, set()):
            problems.append("{!r} was excluded from the control".format(name))

    # 3. A duplicate inflates the denominator and deflates the rate.
    if _admissible("left-pad", {"left-pad"}):
        problems.append("a name already sampled was admitted again, which "
                        "inflates the denominator")

    # 4. The keyword set must not fish in the treatment's neighbourhood.
    for term in KEYWORDS:
        if any(bad in term.lower() for bad in EXCLUDE):
            problems.append("keyword {!r} is MCP-adjacent".format(term))

    def fake(term, offset):
        return ["pkg-{}-{}".format(term, offset)]

    # 5. A short sample must say so. It returned 576 of 1,200 in silence.
    names, short = sample(10000, fetch=fake)
    if short <= 0:
        problems.append("a sample that could not reach its target reported no "
                        "shortfall, so an undersized control looks complete")
    if len(names) != len(set(names)):
        problems.append("the sampler returned duplicates")

    # 6. Same seed, same sample, or none of this is reproducible.
    first, _ = sample(40, seed=1, fetch=fake)
    again, _ = sample(40, seed=1, fetch=fake)
    if first != again:
        problems.append("the same seed produced a different sample")
    other, _ = sample(40, seed=2, fetch=fake)
    if first == other:
        problems.append("different seeds produced identical samples, so the "
                        "seed does nothing")

    # 7. The treatment must be read from the survey, not typed into the code.
    #    It was hardcoded, so a corpus re-run would have compared a fresh
    #    control against stale treatment numbers and said nothing.
    with io.open(os.path.join(HERE, "control_sample.py"),
                 encoding="utf-8") as fh:
        src = fh.read()
    after_docstring = src.split('"""', 2)[-1]
    code_only = after_docstring.split("def check(")[0]
    for stale in ("1641", "4.1%"):
        if stale in code_only:
            problems.append(
                "the treatment figure {!r} is hardcoded in the reporting "
                "path; a corpus re-run would compare today's control against "
                "yesterday's treatment".format(stale))

    # 8. The arithmetic, on cases whose answers are known independently.
    ratio, _z, pval, overlap = compare(67, 1641, 6, 576)
    if not (3.5 < ratio < 4.5):
        problems.append("ratio computed as {:.2f}, expected about 3.9"
                        .format(ratio))
    if pval > 0.01:
        problems.append("p computed as {:.4f} on a case that is significant"
                        .format(pval))
    if overlap:
        problems.append("intervals reported as overlapping when they do not")

    ratio, _z, pval, overlap = compare(10, 1000, 10, 1000)
    if not overlap or pval < 0.5:
        problems.append("two identical rates were reported as different")

    # A rate of zero in the control must not become an infinite finding.
    ratio, _z, _p, _o = compare(5, 100, 0, 100)
    if ratio != float("inf"):
        problems.append("a zero-rate control did not produce an undefined "
                        "ratio, so the report would quote a finite one")
    return problems


def main():
    argv = sys.argv[1:]
    if argv and argv[0] == "--check":
        found = check()
        for line in found:
            print("  " + line)
        print("control sampler: {}".format(
            "all hold" if not found else "{} PROBLEM(S)".format(len(found))))
        raise SystemExit(1 if found else 0)

    target = int(argv[0]) if argv else 400
    names, short = sample(target)
    if short > 0:
        print("WARNING: asked for {} and could only reach {}. The keyword by "
              "offset space is exhausted; widen KEYWORDS or OFFSETS before "
              "quoting this as the control size."
              .format(target, len(names)), file=sys.stderr)
    print("control sample: {} npm packages, MCP-adjacent names excluded"
          .format(len(names)), file=sys.stderr)

    rows = install_scripts.survey(names)
    unknown = [r for r in rows if r["status"] == "unknown"]
    hooked = [r for r in rows if r["status"] == "hooks"]
    answered = len(rows) - len(unknown)
    native_control = [r for r in hooked if all(h["ordinary"]
                                               for h in r["hooks"])]

    k1, n1, native_treatment = treatment()
    k2, n2 = len(hooked), answered
    lo1, hi1 = wilson(k1, n1)
    lo2, hi2 = wilson(k2, n2)
    ratio, z, pval, overlap = compare(k1, n1, k2, n2)

    print("")
    print("TREATMENT  npm MCP packages  {:>4}/{:<5} {:5.2f}%  95% CI [{:.2f}, {:.2f}]"
          .format(k1, n1, 100.0 * k1 / n1 if n1 else 0, lo1, hi1))
    print("CONTROL    ordinary npm      {:>4}/{:<5} {:5.2f}%  95% CI [{:.2f}, {:.2f}]"
          .format(k2, n2, 100.0 * k2 / n2 if n2 else 0, lo2, hi2))
    print("")
    print("ratio {:.1f}x    z = {:.2f}    p = {:.5f}    intervals overlap: {}"
          .format(ratio, z, pval, "yes" if overlap else "no"))
    print("")
    print("native builds   treatment {}/{}   control {}/{}"
          .format(native_treatment, k1, len(native_control), k2))
    print("A native module compiling itself is the ordinary reason to have an")
    print("install hook. That is the difference in KIND, and it needs no test.")

    if len(argv) > 1:
        with io.open(argv[1], "w", encoding="utf-8", newline="\n") as fh:
            json.dump({"control": rows, "sampled": len(names),
                       "shortfall": short}, fh, indent=2)
            fh.write("\n")


if __name__ == "__main__":
    main()
