#!/usr/bin/env python3
"""saydo -- put one tool under SayDo and check the result.

One command wraps the pipeline that the tools/ scripts perform separately:
capture the live tool definitions, exercise the server under the conformance
harness, and emit a hash-chained receipt. A stranger with one of the covered
servers installed runs

    saydo verify certivl

and gets reports/certivl.report.json, receipts/certivl.receipt.jsonl, and an
anchor whose head they check in verifier/index.html without trusting us.

This orchestrator shells out to the same tools/ scripts that were tested
individually, under one interpreter, so the path it runs is the path that was
proven. It adds no behavior of its own beyond sequencing and reporting.

Subcommands:
    list                       the servers a plan and declaration exist for
    verify <name>              capture -> harness -> receipt for one server
    check  <name>              validate the declaration against a live capture
    selfcheck                  prove the harness catches the seeded fixture

Every receipt is a draft (status draft, signature null). verify never claims
more than the harness observed, and prints NOT CONFORMANT loudly when a
verdict fails.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS = os.path.join(ROOT, "tools")
sys.path.insert(0, TOOLS)

import plans as plans_mod   # noqa: E402  (path set above)

SCHEMA = os.path.join(ROOT, "spec", "declaration.schema.json")


def _paths(name):
    return {
        "declaration": os.path.join(ROOT, "declarations",
                                    name + ".declaration.json"),
        "seeded_declaration": os.path.join(ROOT, "seeded",
                                           "malserver.declaration.json"),
        "capture": os.path.join(ROOT, "captured", name + ".json"),
        "report": os.path.join(ROOT, "reports", name + ".report.json"),
        "receipts": os.path.join(ROOT, "receipts"),
        "anchor": os.path.join(ROOT, "receipts", name + ".anchor.json"),
    }


def _default_key():
    """The F-Keys signing key if it is present, else None (unsigned draft)."""
    k = os.path.join(ROOT, "keys", "f-keys-poc.private.jwk")
    return k if os.path.exists(k) else None


def _declaration_for(name):
    p = _paths(name)
    if name == "malserver":
        return p["seeded_declaration"]
    return p["declaration"]


def _launch_argv(name, python):
    plan = plans_mod.PLANS.get(name)
    if not plan:
        return None
    if plan.get("script"):
        return [python, plan["script"]]
    return [python, "-c", plan["launch"]]


def _run(argv, quiet=False):
    result = subprocess.run(argv, cwd=TOOLS, capture_output=True, text=True)
    if not quiet:
        out = (result.stdout or "").strip()
        # The interpreter prints a harmless prefix line on this machine; drop
        # it so the CLI's own output is clean.
        for line in out.splitlines():
            if line.strip() and "platform independent libraries" not in line:
                print("   " + line)
    if result.returncode != 0:
        err = (result.stderr or "").strip()
        raise SystemExit("step failed ({}):\n{}".format(argv[1], err))
    return result


def cmd_list(args):
    print("servers with a declaration and an exercise plan:\n")
    for name in sorted(plans_mod.PLANS):
        decl = _declaration_for(name)
        has = "declaration" if os.path.exists(decl) else "NO DECLARATION"
        tag = "  (seeded non-conformant fixture)" if name == "malserver" else ""
        print("  {:<14} {}{}".format(name, has, tag))
    print("\nverify one with:  saydo verify <name>")


def cmd_verify(args):
    name = args.name
    python = args.python or sys.executable
    p = _paths(name)
    declaration = _declaration_for(name)
    if not os.path.exists(declaration):
        raise SystemExit("no declaration for {!r}; try `saydo list`".format(name))
    launch = _launch_argv(name, python)
    if not launch:
        raise SystemExit("no exercise plan for {!r}; the harness needs one "
                         "to know how to drive it".format(name))

    print("saydo verify {}  (interpreter: {})".format(name, python))

    print("\n[1/3] capture live tool definitions")
    _run([python, os.path.join(TOOLS, "capture_tools.py"),
          p["capture"], "--"] + launch)

    print("\n[2/3] exercise under the conformance harness")
    _run([python, os.path.join(TOOLS, "harness.py"),
          declaration, p["capture"], p["report"],
          "--python", python, "--plan", name])

    print("\n[3/3] emit the hash-chained receipt")
    receipt_cmd = [python, os.path.join(TOOLS, "receipt.py"),
                   p["report"], declaration, p["capture"], p["receipts"],
                   "--at", args.at]
    key = args.sign or _default_key()
    if key:
        receipt_cmd += ["--sign", key]
    _run(receipt_cmd)

    with open(p["anchor"], encoding="utf-8") as fh:
        anchor = json.load(fh)
    with open(p["report"], encoding="utf-8") as fh:
        report = json.load(fh)

    print("\n" + "=" * 60)
    verdict = "CONFORMANT" if anchor["conformant"] else "NOT CONFORMANT"
    print("  {}   {}".format(name, verdict))
    print("  tally      {}".format(report["tally"]))
    if report["findings"]:
        print("  findings   {}".format(len(report["findings"])))
        for f in report["findings"]:
            print("    - {}: {} ({})".format(f["kind"], f.get("tool", ""),
                                              f["detail"]))
    print("  receipt    {}".format(
        os.path.relpath(os.path.join(p["receipts"], name + ".receipt.jsonl"),
                        ROOT)))
    print("  head       {}".format(anchor["head"]))
    # The model-facing read: the same verdict an agent would gate on.
    import status as status_mod
    with open(os.path.join(p["receipts"], name + ".receipt.jsonl"),
              encoding="utf-8") as fh:
        st = status_mod.build(fh.readlines(), anchor)
    print("  status     {}: {}".format(st["verdict"], st["advice"]))
    print("=" * 60)
    print("\ncheck it yourself: open verifier/index.html, paste the receipt "
          "and\nthe anchor ({}). No account, no network."
          .format(os.path.relpath(p["anchor"], ROOT)))
    return 0 if anchor["conformant"] else 1


def cmd_status(args):
    """Print the compact saydo/status an agent reads to gate a tool."""
    import status as status_mod
    p = _paths(args.name)
    rec, anc = (os.path.join(p["receipts"], args.name + ".receipt.jsonl"),
                p["anchor"])
    if not (os.path.exists(rec) and os.path.exists(anc)):
        print(json.dumps({"saydoStatus": "0.1.0",
                          "subject": {"name": args.name},
                          "verdict": "unknown",
                          "advice": "No receipt on record; treat as untrusted. "
                                    "Run `saydo verify {}` first.".format(
                                        args.name)}, indent=2))
        return 0
    with open(rec, encoding="utf-8") as fh:
        st = status_mod.build(fh.readlines(), json.load(open(anc, encoding="utf-8")))
    print(json.dumps(st, indent=2, ensure_ascii=False))
    return 0


def cmd_check(args):
    name = args.name
    p = _paths(name)
    declaration = _declaration_for(name)
    argv = [sys.executable, os.path.join(TOOLS, "decl_check.py"),
            SCHEMA, declaration]
    if os.path.exists(p["capture"]):
        argv.append(p["capture"])
    result = _run(argv, quiet=True)
    print((result.stdout or "").strip().splitlines()[-1])
    return 0


def cmd_selfcheck(args):
    """For a skeptic: show the harness catches a server that lies, and the
    declaration validator rejects five kinds of tampering."""
    python = args.python or sys.executable
    print("verify-the-verifier: the harness must catch the seeded fixture,\n"
          "and the declaration validator must reject tampering.\n")

    print("[1] harness vs seeded non-conformant server")
    rc = cmd_verify(argparse.Namespace(name="malserver", python=python,
                                       at=args.at, sign=None))
    caught = (rc == 1)
    print("\n   seeded server caught: {}".format("YES" if caught else
                                                 "NO -- HARNESS BROKEN"))

    print("\n[2] declaration validator vs five mutations")
    p = _paths("certivl")
    _run([python, os.path.join(TOOLS, "decl_check.py"), "selfcheck",
          SCHEMA, p["declaration"], p["capture"]])

    if not caught:
        raise SystemExit("selfcheck FAILED: the harness did not catch the "
                         "seeded server")
    print("\nselfcheck passed: the harness can fail, so a pass means something.")
    return 0


def main():
    ap = argparse.ArgumentParser(prog="saydo", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list").set_defaults(fn=cmd_list)

    v = sub.add_parser("verify")
    v.add_argument("name")
    v.add_argument("--python", help="interpreter that runs the server "
                                    "(default: this one)")
    v.add_argument("--at", default="1970-01-01T00:00:00Z",
                   help="generatedAt stamp for a reproducible receipt")
    v.add_argument("--sign", metavar="PRIVATE_JWK",
                   help="private-key JWK to sign the receipt (default: the "
                        "F-Keys key under keys/ if present, else unsigned)")
    v.set_defaults(fn=cmd_verify)

    c = sub.add_parser("check")
    c.add_argument("name")
    c.set_defaults(fn=cmd_check)

    st = sub.add_parser("status")
    st.add_argument("name")
    st.set_defaults(fn=cmd_status)

    s = sub.add_parser("selfcheck")
    s.add_argument("--python")
    s.add_argument("--at", default="1970-01-01T00:00:00Z")
    s.set_defaults(fn=cmd_selfcheck)

    args = ap.parse_args()
    raise SystemExit(args.fn(args) or 0)


if __name__ == "__main__":
    main()
