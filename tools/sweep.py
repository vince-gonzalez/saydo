"""Run SayDo across a set of third-party MCP servers and collect the findings.

For each server: capture its tools, infer a conservative declaration, exercise
it generically behind the boundary proxy and the audit hook, and record where
its behavior exceeded a conservative reading of its description. The output is
a corpus -- one status per server plus the specific findings -- and a readable
summary.

This is deliberately a LOWER BOUND. Servers are driven with benign placeholder
arguments, so a tool that needs a specific valid input to act may do little and
appear cleaner than it is; that is noted per server. Findings here are things
SayDo actually observed, not things it guessed.

Usage:
    python sweep.py <server_python> <out_dir>
where server_python is the interpreter that has the servers installed.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import capture_tools
import infer_declaration
import plans as plans_mod
import harness
import status as status_mod


def _scripts_dir(server_python):
    return os.path.dirname(os.path.abspath(server_python))


def servers(server_python):
    db = os.path.join(tempfile.gettempdir(), "saydo-sweep-sqlite.db")
    ext = ".exe" if os.name == "nt" else ""
    sqlite_exe = os.path.join(_scripts_dir(server_python),
                              "mcp-server-sqlite" + ext)
    return [
        {"name": "mcp-server-time", "purl": "pkg:pypi/mcp-server-time",
         "argv": [server_python, "-m", "mcp_server_time"],
         "expected": "timezone math; should touch nothing"},
        {"name": "mcp-server-fetch", "purl": "pkg:pypi/mcp-server-fetch",
         "argv": [server_python, "-m", "mcp_server_fetch"],
         "expected": "fetches URLs; network by design"},
        {"name": "mcp-server-git", "purl": "pkg:pypi/mcp-server-git",
         "argv": [server_python, "-m", "mcp_server_git"],
         "expected": "git operations; subprocess + filesystem likely"},
        {"name": "mcp-server-sqlite", "purl": "pkg:pypi/mcp-server-sqlite",
         "argv": [sqlite_exe, "--db-path", db],
         "expected": "sqlite; filesystem writes likely"},
    ]


def run_one(spec, server_python):
    argv = spec["argv"]
    try:
        capture = capture_tools.capture(argv)
    except Exception as e:
        return {"name": spec["name"], "verdict": "unstartable",
                "error": "{}: {}".format(type(e).__name__, e),
                "expected": spec["expected"]}

    declaration = infer_declaration.infer(capture, purl=spec["purl"],
                                          supplier=spec["name"])
    plan = plans_mod.synth_plan(capture, argv)

    report = harness.run_conformance(spec["name"], plan, declaration,
                                     capture, server_python)

    # A receipt makes the run verifiable; the status is the compact read.
    from receipt import build as build_receipt, canonical
    chain, anchor = build_receipt(report, declaration, capture,
                                  "1970-01-01T00:00:00Z")
    status = status_mod.build([canonical(r) + "\n" for r in chain.rows], anchor)

    fails = [v for v in report["verdicts"] if v["verdict"] == "fail"]
    return {
        "name": spec["name"],
        "expected": spec["expected"],
        "tools": [t["name"] for t in capture["tools"]],
        "verdict": status["verdict"],
        "tally": report["tally"],
        "findings": [{"invariant": v["id"], "type": v["type"],
                      "evidence": v["evidence"]} for v in fails],
        "receipt_head": anchor["head"],
    }


def write_report(corpus, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "corpus.json"), "w", encoding="utf-8",
              newline="\n") as fh:
        json.dump(corpus, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    lines = []
    W = lines.append
    W("# What MCP tools actually do — a first SayDo sweep\n")
    W("DRAFT. A conservative behavioral sweep of {} third-party MCP servers, "
      "run with SayDo on {}. Every finding is something the harness OBSERVED, "
      "not inferred from the description. It is a lower bound: servers were "
      "driven with benign placeholder arguments, so tools needing specific "
      "valid input may do less here than in real use.\n".format(
          len(corpus["servers"]), corpus["date"]))
    total_findings = sum(len(s.get("findings", [])) for s in corpus["servers"])
    W("Headline: {} of {} servers touched the network, the filesystem, or "
      "another process in a way their terse tool descriptions do not state; "
      "{} such observations in total.\n".format(
          sum(1 for s in corpus["servers"] if s.get("findings")),
          len(corpus["servers"]), total_findings))
    W("How to read this. A finding is not an accusation. Some are surprising "
      "(a URL fetcher that also spawns a subprocess); others are expected of "
      "the tool but unstated where an agent reads it (a git tool that writes "
      "inside .git and shells out to git). The point is the same: the actual "
      "footprint is made visible and verifiable, instead of left to a "
      "one-line description. Servers that show no finding were either clean "
      "or not fully exercised by benign input; both are marked, and neither "
      "is a clean bill.\n")
    W("This write-up is a DRAFT and its wording is a placeholder. Any public "
      "version ships in the owner's words.\n")
    for s in corpus["servers"]:
        W("## {}".format(s["name"]))
        W("- expected: {}".format(s.get("expected", "")))
        if s["verdict"] == "unstartable":
            W("- could not start under the harness: {}\n".format(s.get("error")))
            continue
        W("- tools: {}".format(", ".join(s.get("tools", []))))
        W("- verdict: **{}**  (checks: {})".format(s["verdict"], s.get("tally")))
        if s.get("findings"):
            W("- behavior beyond a conservative envelope:")
            for f in s["findings"]:
                W("  - `{}` ({}): {}".format(f["invariant"], f["type"],
                                             f["evidence"]))
        else:
            W("- no behavior beyond the conservative envelope was observed "
              "under benign input.")
        W("- receipt head: `{}`\n".format(s["receipt_head"]))
    with open(os.path.join(out_dir, "STATE-OF-MCP-DRAFT.md"), "w",
              encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    server_python, out_dir = sys.argv[1], sys.argv[2]
    plans_mod.write_fixtures()
    results = []
    for spec in servers(server_python):
        print("sweeping {} ...".format(spec["name"]))
        try:
            r = run_one(spec, server_python)
        except Exception as e:
            r = {"name": spec["name"], "verdict": "error",
                 "error": "{}: {}".format(type(e).__name__, e)}
        v = r.get("verdict")
        nf = len(r.get("findings", []))
        print("  -> {}  ({} finding(s))".format(v, nf))
        results.append(r)
    corpus = {"date": "2026-08-29", "harness": harness.MONITOR_DESC,
              "servers": results}
    write_report(corpus, out_dir)
    print("\nwrote {}/corpus.json and STATE-OF-MCP-DRAFT.md".format(out_dir))


if __name__ == "__main__":
    main()
