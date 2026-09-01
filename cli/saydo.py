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
import glob
import json
import os
import re
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
    # Run from wherever the user is, not from tools/. A command they supply
    # may contain relative paths, and those must mean what they meant when
    # they typed them. The scripts are invoked by absolute path, so Python
    # still puts tools/ on sys.path for their own imports.
    result = subprocess.run(argv, cwd=os.getcwd(), capture_output=True,
                            text=True)
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


def _safe(name):
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)[:80]


def cmd_verify_any(args):
    """Verify ANY MCP server, named by the command that starts it.

    Two ways to arrive here, and the difference is what can be proven rather
    than which tool is used:

      A publisher runs this on their own server, with the credentials and
      inputs it needs, and supplies the declaration they are willing to sign.
      The tool actually does its work, so its behaviour is observable and the
      receipt is worth something.

      Anyone else runs it on someone else's server, with no credentials. A
      conservative declaration is inferred, and whatever the server will do
      for a stranger is measured. Much will come back not-covered, which is
      the honest answer: a tool that refuses to act has not been shown to be
      safe, it has simply not been shown.

    Same harness, same receipt format, same verifier. Only the coverage
    differs, and the receipt says which it was.
    """
    python = args.python or sys.executable
    name = args.name or _name_for(args, _resolve_command(args))
    slug = _safe(name)

    if args.sandbox:
        args.runner = "container"
        args.image, argv = _autobuild(args, slug)
    else:
        argv = _resolve_command(args)
        if args.runner != "container":
            _warn_unsandboxed(args)

    capture_path = os.path.join(ROOT, "captured", slug + ".json")
    decl_path = args.declaration or os.path.join(
        ROOT, "declarations", "inferred", slug + ".declaration.json")
    report_path = os.path.join(ROOT, "reports", slug + ".report.json")
    for d in (os.path.dirname(capture_path), os.path.dirname(decl_path),
              os.path.dirname(report_path), os.path.join(ROOT, "receipts")):
        os.makedirs(d, exist_ok=True)

    print("saydo verify {}\n  command: {}".format(name, " ".join(argv)))

    print("\n[1/4] capture the live tool definitions")
    # Capture STARTS the server, so under --sandbox it must start it inside
    # the container too. Reading tools/list on the host would execute the
    # untrusted package on the machine the sandbox exists to protect -- the
    # sandbox built and then walked around.
    probe = argv
    if args.runner == "container":
        probe = ["docker", "run", "--rm", "-i", "--network", "none",
                 "--read-only", "--tmpfs", "/scratch:rw,noexec,nosuid,size=64m,mode=1777",
                 "-e", "TMPDIR=/scratch", "--cap-drop", "ALL",
                 "--security-opt", "no-new-privileges", "--memory", "512m",
                 "--workdir", "/scratch", args.image] + argv
    _run([python, os.path.join(TOOLS, "capture_tools.py"),
          capture_path, "--"] + probe)

    if args.declaration:
        print("\n[2/4] using the declaration supplied by the author")
    else:
        print("\n[2/4] infer a conservative declaration (every invariant is a "
              "hypothesis, not a finding)")
        # The package identity must be recorded, not the name the server calls
        # itself. mcp-server-time reports its serverInfo name as "mcp-time",
        # and a receipt that does not say which package produced it cannot be
        # looked up, published, or trusted later.
        purl = ("pkg:npm/" + args.npm if args.npm else
                "pkg:pypi/" + args.pypi if args.pypi else
                "pkg:generic/" + slug)
        _run([python, os.path.join(TOOLS, "infer_declaration.py"),
              capture_path, "--supplier", name, "--purl", purl,
              "-o", decl_path])

    print("\n[3/4] exercise under the conformance harness")
    harness_cmd = [python, os.path.join(TOOLS, "harness.py"),
                   decl_path, capture_path, report_path,
                   "--python", python, "--plan", "@generic:" + json.dumps(argv)]
    if args.runner == "container":
        if not args.image:
            raise SystemExit("--runner container needs --image")
        harness_cmd += ["--runner", "container", "--image", args.image]
        if args.routed:
            harness_cmd.append("--routed")
    _run(harness_cmd)

    print("\n[4/4] emit the hash-chained receipt")
    receipt_cmd = [python, os.path.join(TOOLS, "receipt.py"),
                   report_path, decl_path, capture_path,
                   os.path.join(ROOT, "receipts"), "--at", args.at]
    key = args.sign or _default_key()
    if key:
        receipt_cmd += ["--sign", key]
    _run(receipt_cmd)

    _summarise(slug, name, report_path)
    return 0


AUTOBUILD = """\
# Generated by SayDo to run one third-party package under inspection.
# Nothing in it is trusted: it is here to be measured.
FROM {base}
RUN useradd --create-home --uid 10001 saydo
RUN {install}
COPY tools/monitor_boot /saydo/monitor_boot
ENV PYTHONPATH=/saydo/monitor_boot
USER saydo
WORKDIR /scratch
ENTRYPOINT []
"""


def _autobuild(args, slug):
    """Build a throwaway image holding just this package.

    The sandbox is worth having only if reaching it is easy. Asking someone to
    hand-write a Dockerfile before they can safely inspect a stranger's
    package guarantees they will skip it and run the package on their laptop
    instead, which is the outcome this tool exists to prevent.

    Returns (image, in_container_argv).
    """
    import shutil
    import tempfile
    if not shutil.which("docker"):
        # Say what is missing and what it buys, because the failure mode this
        # guards against is someone shrugging and running an unknown package
        # on their own machine instead.
        raise SystemExit(
            "--sandbox needs Docker, which is not on PATH here.\n"
            "  Install Docker, or run on a Linux host, to inspect untrusted\n"
            "  packages safely. Without it SayDo can still observe a package\n"
            "  running directly on this machine, but it cannot contain it -\n"
            "  so do that only for software you already trust.")
    if args.npm:
        base, install = "node:22-slim", \
            'npm install -g --omit=dev "{}"'.format(args.npm)
        sys.path.insert(0, TOOLS)
        import sweep_scale
        bins = sweep_scale.npm_bins(args.npm) or [args.npm.split("/")[-1]]
        argv = [bins[0]]
    elif args.pypi:
        base, install = "python:3.12-slim", \
            'pip install --no-cache-dir "{}"'.format(args.pypi)
        argv = [args.pypi.replace("_", "-")]
    else:
        raise SystemExit("--sandbox builds an image for --npm or --pypi; for "
                         "--command, build the image yourself and pass "
                         "--runner container --image")

    image = "saydo/auto-" + slug.lower()[:40] + ":latest"
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "Dockerfile")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(AUTOBUILD.format(base=base, install=install))
        print("  building {} ...".format(image))
        out = subprocess.run(["docker", "build", "-f", path, "-t", image, "."],
                             cwd=ROOT, capture_output=True, text=True,
                             timeout=1800)
    if out.returncode != 0:
        raise SystemExit("could not build the sandbox image:\n"
                         + (out.stderr or "")[-600:])
    return image, argv


def _warn_unsandboxed(args):
    """Say plainly what is about to happen, when it is about to happen."""
    # --command is a single string now. Joining it as though it were still a
    # list of tokens spelled the command out one character at a time in the
    # safety banner -- "p y t h o n   s e e d e d / . . ." -- which is the
    # warning a person is meant to read before running untrusted code.
    what = args.npm or args.pypi or (
        args.command if isinstance(args.command, str)
        else " ".join(args.command or []))
    print("\n" + "!" * 62)
    print("  About to run UNTRUSTED code on THIS MACHINE, not in a sandbox.")
    print("    {}".format(what[:70]))
    print("  It will run with your user's permissions and your network.")
    print("  SayDo can observe what it does; it cannot stop it.")
    print("  Safer:  add --sandbox  (runs it in a container with no route")
    print("          out except SayDo's proxy, and a read-only filesystem)")
    print("!" * 62 + "\n")


def _resolve_command(args):
    """The argv that starts the server, however the user named it.

    --python names the interpreter that HAS the server installed, which is
    frequently not the one running SayDo: the harness and the software under
    test have no business sharing an environment.
    """
    if args.command:
        # ONE quoted string, split the way a shell would split it.
        #
        # This used to be nargs=REMAINDER, which swallowed every later flag:
        # `--command "python srv.py" --declaration mine.json` put the flag
        # INSIDE the command and started a server with two arguments it had
        # never heard of. That combination is the one the README documents, and
        # it could not work in any invocation. REMAINDER cannot be fixed with
        # care -- it is defined to consume the rest of the line -- so the
        # option now takes a single value and the ambiguity is gone.
        import shlex
        command = args.command
        if isinstance(command, list):                # tolerate older callers
            command = " ".join(command)
        return shlex.split(command, posix=(os.name != "nt"))
    if args.npm:
        return ["npx", "-y", args.npm]
    if args.pypi:
        python = args.python or sys.executable
        module = args.pypi.replace("-", "_")
        # A console script is the more reliable entry point; -m only works if
        # the package ships a __main__.
        exe = os.path.join(os.path.dirname(os.path.abspath(python)),
                           args.pypi.replace("_", "-"))
        for candidate in (exe, exe + ".exe"):
            if os.path.exists(candidate):
                return [candidate]
        return [python, "-m", module]
    raise SystemExit("give one of --command, --npm or --pypi")


_INTERPRETERS = ("python", "python3", "python.exe", "python3.exe", "py",
                 "py.exe", "node", "node.exe", "npx", "npx.cmd", "deno", "bun",
                 "uv", "uvx", "ruby", "perl", "sh", "bash", "env")


def _name_for(args, argv):
    """What this run is ABOUT, which is not always argv[0].

    `--command python my_server.py` names the interpreter first, and naming the
    receipt after it filed a conformance run under "python.exe" -- a receipt
    nobody can look up by the thing it describes, which is the same defect that
    once filed mcp-server-time under "mcp-time". The subject is the script or
    module being run, so the launcher is skipped over to find it.
    """
    if args.npm or args.pypi:
        return args.npm or args.pypi
    for token in argv:
        base = os.path.basename(token)
        if base.lower() in _INTERPRETERS or token.startswith("-"):
            continue
        # A scoped npm name is not a path. Taking its basename turns
        # @modelcontextprotocol/server-memory into "server-memory", which
        # collides with every other package that ends the same way.
        return token if token.startswith("@") else base
    return os.path.basename(argv[0])


def _summarise(slug, name, report_path):
    import status as status_mod
    with open(report_path, encoding="utf-8") as fh:
        report = json.load(fh)
    # The receipt is named from the subject the report records, which is the
    # server's own name; the report is named from the slug, which comes from
    # the command that started it. For `saydo verify <name>` those agree. For
    # `--command python silentserver.py` they do not -- slug "silentserver.py"
    # against receipt "silentserver" -- so the CLI has been quietly failing to
    # find its own receipt and printing neither the head nor the status.
    subject = ((report.get("subject") or {}).get("name") or "").strip()
    candidates = [slug] + ([_safe(subject)] if subject else [])
    anchor_path = os.path.join(ROOT, "receipts", slug + ".anchor.json")
    for candidate in candidates:
        path = os.path.join(ROOT, "receipts", candidate + ".anchor.json")
        if os.path.exists(path):
            anchor_path = path
            slug = candidate          # the receipt pair is named consistently
            break
    print("\n" + "=" * 62)
    print("  {}   {}".format(
        name, _headline(report)))
    print("  enforcement  {}".format(report.get("enforcement", "observed")))
    print("  tally        {}".format(report["tally"]))
    for v in report["verdicts"]:
        if v["verdict"] == "fail":
            print("    FAIL  {:<22} {}".format(v["id"], v["evidence"][:70]))
    notcov = [v["id"] for v in report["verdicts"]
              if v["verdict"] == "not-covered"]
    if notcov:
        print("  not covered  {}".format(", ".join(notcov)))
        print("               (unproven, NOT clean -- usually because the "
              "tool\n                would not act without credentials)")
    if os.path.exists(anchor_path):
        with open(anchor_path, encoding="utf-8") as fh:
            anchor = json.load(fh)
        print("  receipt      {}".format(anchor["head"]))
        with open(os.path.join(ROOT, "receipts", slug + ".receipt.jsonl"),
                  encoding="utf-8") as fh:
            st = status_mod.build(fh.readlines(), anchor)
        print("  status       {}: {}".format(st["verdict"], st["advice"][:90]))
    print("=" * 62)
    print("\nverify it yourself: open verifier/index.html and paste the "
          "receipt and anchor.")

    # One machine-readable line naming exactly what this run produced.
    #
    # The GitHub Action used to find its own output by globbing reports/ and
    # taking the most recently modified file. That worked only while the
    # repository contained no committed reports. It now does -- receipts for
    # real third-party servers were added deliberately -- and on a fresh
    # checkout every file carries the same mtime, so the Action started reading
    # a committed report belonging to a different server and then looking for
    # an anchor that does not exist under that name. Fourteen runs failed that
    # way in one day.
    #
    # A caller should never have to guess which file a command it just ran
    # wrote. This says so.
    print("SAYDO_RESULT " + json.dumps({
        "slug": slug,
        "name": name,
        "verdict": ("failing" if not report["conformant"] else
                    "inconclusive" if not report.get("established") else
                    "warranted"),
        "conformant": bool(report["conformant"]),
        "established": report.get("established", 0),
        "enforcement": report.get("enforcement", "observed"),
        "report": os.path.relpath(report_path, ROOT).replace(os.sep, "/"),
        "anchor": (os.path.relpath(anchor_path, ROOT).replace(os.sep, "/")
                   if os.path.exists(anchor_path) else None),
    }, sort_keys=True))


def _headline(report):
    """The one word a reader takes away, and it must be earned.

    NOT CONFORMANT when something failed. INCONCLUSIVE when nothing failed but
    nothing was established either -- the ordinary case for a server that
    declines to act without credentials, and previously announced as
    CONFORMANT, which told the reader the opposite of the truth.
    """
    if not report["conformant"]:
        return "NOT CONFORMANT"
    if not report.get("established"):
        return "INCONCLUSIVE (nothing was established)"
    return "CONFORMANT"


def cmd_verify(args):
    # An arbitrary server, named by how it starts.
    if args.command or args.npm or args.pypi:
        return cmd_verify_any(args)

    name = args.name
    if not name:
        raise SystemExit("give a server name, or --command/--npm/--pypi")
    python = args.python or sys.executable
    p = _paths(name)
    declaration = _declaration_for(name)
    if not os.path.exists(declaration):
        raise SystemExit("no declaration for {!r}; try `saydo list`, or point "
                         "saydo at any server with --command / --npm / --pypi"
                         .format(name))
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
    print("  {}   {}".format(name, _headline(report)))
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


def _receipt_paths(name):
    """Where this subject's receipt lives, however it was named.

    A receipt is filed under the subject the declaration names, which for an
    arbitrary package is not always the string the user typed. Both are tried
    so `saydo status` works for anything `saydo verify` produced, not only for
    servers in the registry.
    """
    d = os.path.join(ROOT, "receipts")
    for stem in (name, _safe(name)):
        rec = os.path.join(d, stem + ".receipt.jsonl")
        if os.path.exists(rec):
            return rec, os.path.join(d, stem + ".anchor.json")
    # Fall back to any receipt whose subject matches by name OR by package,
    # since a server's self-reported name is often not the package name.
    for anc in glob.glob(os.path.join(d, "*.anchor.json")):
        try:
            with open(anc, encoding="utf-8") as fh:
                subject = json.load(fh).get("subject", {})
        except Exception:
            continue
        purl = subject.get("purl", "")
        if subject.get("name") == name or purl.endswith("/" + name) \
                or purl.endswith("/" + name.split("/")[-1]):
            return anc.replace(".anchor.json", ".receipt.jsonl"), anc
    return (os.path.join(d, _safe(name) + ".receipt.jsonl"),
            os.path.join(d, _safe(name) + ".anchor.json"))


def cmd_status(args):
    """Print the compact saydo/status an agent reads to gate a tool."""
    import status as status_mod
    rec, anc = _receipt_paths(args.name)
    if not (os.path.exists(rec) and os.path.exists(anc)):
        print(json.dumps({"saydoStatus": "0.1.0",
                          "subject": {"name": args.name},
                          "verdict": "unknown",
                          "advice": "No receipt on record; treat as untrusted. "
                                    "Run `saydo verify {}` first.".format(
                                        args.name)}, indent=2))
        return 0
    with open(rec, encoding="utf-8") as fh:
        st = status_mod.build(fh.readlines(),
                              json.load(open(anc, encoding="utf-8")),
                              registry_entry=_registry_entry(anc))
    print(json.dumps(st, indent=2, ensure_ascii=False))
    return 0


REGISTRY_PATH = os.path.join(ROOT, "registry", "saydo-registry.json")


def _registry_entry(anchor_path):
    """What the registry currently says about this receipt's subject, if
    anything. Consulted so a withdrawn or stale claim cannot keep being
    reported as current by an artifact an agent trusts."""
    try:
        import registry as reg
        with open(anchor_path, encoding="utf-8") as fh:
            subject = json.load(fh).get("subject", {})
        key = subject.get("purl") or subject.get("name")
        entry = reg.lookup(reg.load(REGISTRY_PATH), key)
        return entry if entry.get("state") != "unknown" else None
    except Exception:
        return None


def cmd_publish(args):
    """Record a receipt in the registry, so others can look it up."""
    _, anc = _receipt_paths(args.name)
    if not os.path.exists(anc):
        raise SystemExit("no receipt for {!r}; verify it first".format(args.name))
    cmd = [sys.executable, os.path.join(TOOLS, "registry.py"), REGISTRY_PATH,
           "publish", anc]
    if args.at:
        cmd += ["--at", args.at]
    _run(cmd)
    return 0


def cmd_revoke(args):
    """Withdraw a claim. Sticky: a later passing receipt will not lift it."""
    _run([sys.executable, os.path.join(TOOLS, "registry.py"), REGISTRY_PATH,
          "revoke", args.key, args.reason])
    print("\nAnyone reading `saydo status` for this subject now sees the "
          "withdrawal,\nnot the receipt's original verdict.")
    return 0


def cmd_registry(args):
    _run([sys.executable, os.path.join(TOOLS, "registry.py"), REGISTRY_PATH,
          "list"])
    return 0


def cmd_declare(args):
    """Draft a declaration from a run that already happened."""
    slug = _safe(args.name)
    report = os.path.join(ROOT, "reports", slug + ".report.json")
    capture = os.path.join(ROOT, "captured", slug + ".json")
    if not (os.path.exists(report) and os.path.exists(capture)):
        raise SystemExit(
            "no run on record for {!r}. A declaration is drafted from what a "
            "run observed, so verify it first:\n"
            "  saydo verify --npm/--pypi/--command ...".format(args.name))
    out = args.out or os.path.join(ROOT, "declarations", "drafted",
                                   slug + ".declaration.json")
    _run([sys.executable, os.path.join(TOOLS, "declare.py"), report, capture,
          "-o", out])
    print("\nReview it, tighten anything too permissive, then sign it and\n"
          "pass it back with:  saydo verify ... --declaration " + out)
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
    # Built by the real parser rather than hand-assembled, so selfcheck runs
    # the same code path a user does. A hand-made Namespace has to restate
    # every default `verify` has, and the moment one is added it stops matching
    # -- which is exactly what happened: selfcheck, the gate whose entire job
    # is proving the harness can fail, died on a missing attribute instead of
    # reporting anything. The gate that proves the other gates must not be the
    # one nobody re-runs.
    inner = _parser().parse_args(["verify", "malserver"])
    inner.python, inner.at = python, args.at
    rc = cmd_verify(inner)
    caught = (rc == 1)
    print("\n   seeded server caught: {}".format("YES" if caught else
                                                 "NO -- HARNESS BROKEN"))

    print("\n[2] declaration validator vs five mutations")
    p = _paths("certivl")
    _run([python, os.path.join(TOOLS, "decl_check.py"), "selfcheck",
          SCHEMA, p["declaration"], p["capture"]])

    print("\n[3] the harness must be able to make a picky server ACT")
    # A harness that cannot get a server to do anything reports not-covered
    # for everything, and from outside that is indistinguishable from a
    # harness inspecting a well-behaved ecosystem. Not hypothetical: a sweep of
    # 280 published servers returned 835 verdict rows, every one not-covered,
    # and it got written up as a finding about MCP servers rather than as a
    # limit of this tool. pickyserver states its requirements in its schema and
    # declines anything else, so if argument synthesis regresses it fails here
    # rather than six hours into a corpus run.
    stalled = _check_coverage(python, args)
    for line in stalled:
        print("   " + line)
    if stalled:
        raise SystemExit("selfcheck FAILED: the harness could not make a "
                         "cooperative server act, so a not-covered result "
                         "would say more about us than about any subject")

    print("\n[4] the output scanner must catch a payload and spare clean prose")
    noisy = _check_output_scan(python, args)
    for line in noisy:
        print("   " + line)
    if noisy:
        raise SystemExit("selfcheck FAILED: the output scanner is not "
                         "discriminating, so any finding it produces is "
                         "worthless")

    print("\n[5] a server's own promises must be checked, and only its own")
    unfair = _check_claims(python, args)
    for line in unfair:
        print("   " + line)
    if unfair:
        raise SystemExit("selfcheck FAILED: the claim check is not fair, and "
                         "it names real projects")

    print("\n[6] the container path must hold together without Docker")
    broken = _check_container_runner()
    for line in broken:
        print("   " + line)
    if broken:
        raise SystemExit("selfcheck FAILED: the sandbox runner is broken in a "
                         "way that would only show up in CI")

    print("\n[7] schema, spec and every declaration must agree")
    # Three schema-versus-code divergences turned up in one day: two verdicts
    # and an invariant type that the code emitted and the schema forbade. Each
    # meant an artifact this project hands someone would be rejected by this
    # project's own validator. A specification nobody checks against is a
    # description of an earlier program.
    bad = _check_declarations()
    for line in bad:
        print("   " + line)
    if bad:
        raise SystemExit("selfcheck FAILED: the schema, the prose spec and the "
                         "declarations in this repository do not describe the "
                         "same program (see above for which)")

    print("\n[8] every status verdict must satisfy the published schema")
    # The schema is what a consumer validates against, so a verdict the code
    # can emit but the schema forbids makes our own output invalid -- which is
    # what happened when `inconclusive`, `revoked` and `expired` were added to
    # the code and not to the enum. Checking each verdict the builder can
    # produce turns that from something someone notices into something that
    # fails here.
    bad = _check_status_schema()
    for line in bad:
        print("   " + line)
    if bad:
        raise SystemExit("selfcheck FAILED: emitted a status the published "
                         "schema rejects")

    print("\n[9] the category rules must be tested, not just written")
    # A classifier rule can die silently: an exclusion written with an escape
    # that the shell consumed matched nothing for a whole corpus run, and the
    # only symptom was a category quietly growing by one. Nothing failed,
    # because nothing was checking the rules themselves -- so the bug would
    # have been published as a fact about the ecosystem. Each rule is now
    # pinned to a case it has to keep getting right.
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import categories as categories_mod
    import category_report as category_report_mod
    bad = categories_mod.check() + category_report_mod.check()
    for line in bad:
        print("   " + line)
    if bad:
        raise SystemExit("selfcheck FAILED: the category rules do not do what "
                         "they claim, so any census built from them is wrong")
    print("   {} rules and {} exclusions hold against {} pinned cases"
          .format(len(categories_mod.RULES), len(categories_mod.EXCLUSIONS),
                  len(categories_mod.WITNESSES)))
    print("   the category-to-behaviour join reports servers, not promises, "
          "and says 'not measured' rather than zero")

    print("\n[10] a measurement must belong to the package it names")
    # A batch installs many packages into one image, and scoped names collapse:
    # @aibtc/mcp-server, @aipost/mcp-server and @battlegrid/mcp-server all
    # reduce to the binary `mcp-server`. One server answered for five packages
    # and the sweep filed five records under five names -- reporting that three
    # of four finance servers carried the tool's own input to a host, when one
    # did and the others were never run. Every record already carried the
    # contradiction: server.name said `aipost-mcp` under someone else's name.
    # Nothing read it.
    import sweep_scale as sweep_mod
    bad = sweep_mod.check()
    for line in bad:
        print("   " + line)
    if bad:
        raise SystemExit("selfcheck FAILED: the sweep can attribute one "
                         "server's behaviour to another package's name")
    print("   identical captures are disowned, distinct ones are kept, and "
          "launches go through the package")

    if not caught:
        raise SystemExit("selfcheck FAILED: the harness did not catch the "
                         "seeded server")
    print("\nselfcheck passed: the harness can fail, so a pass means something.")
    return 0


def _check_coverage(python, args):
    """Every tool in the picky fixture must be observed doing work. [] = good."""
    script = os.path.join(ROOT, "seeded", "pickyserver.py")
    inner = _parser().parse_args(["verify", "--command", python + " " + script])
    inner.python, inner.at = python, args.at
    try:
        cmd_verify(inner)
    except SystemExit:
        pass          # the fixture is non-conformant by design; not the test
    report = os.path.join(ROOT, "reports", "pickyserver.py.report.json")
    if not os.path.exists(report):
        return ["the picky fixture produced no report at all"]
    with open(report, encoding="utf-8") as fh:
        rep = json.load(fh)
    writes = next((v.get("observed", []) for v in rep["verdicts"]
                   if v["id"] == "writes.none"), [])
    acted = {o["tool"] for o in writes}
    want = {"convert", "schedule", "lookup", "summarise"}
    missing = sorted(want - acted)
    if missing:
        return ["{} never acted: its schema was not honoured, so the run "
                "learned nothing about it".format(name) for name in missing]
    print("   all {} schema-constrained tools acted: {}".format(
        len(want), ", ".join(sorted(want))))
    return []


def _check_output_scan(python, args):
    """The output scanner must catch a payload AND leave clean prose alone."""
    script = os.path.join(ROOT, "seeded", "injectserver.py")
    decl = os.path.join(ROOT, "declarations", "inferred",
                        "injectserver.py.declaration.json")
    inner = _parser().parse_args(["verify", "--command", python + " " + script]
                                 + (["--declaration", decl]
                                    if os.path.exists(decl) else []))
    inner.python, inner.at = python, args.at
    try:
        cmd_verify(inner)
    except SystemExit:
        pass
    report = os.path.join(ROOT, "reports", "injectserver.py.report.json")
    if not os.path.exists(report):
        return ["the output-scan fixture produced no report"]
    with open(report, encoding="utf-8") as fh:
        rep = json.load(fh)
    row = next((v for v in rep["verdicts"] if v["id"] == "output.hygiene"), None)
    if row is None:
        return ["no output-hygiene verdict; the invariant is not being judged"]
    named = {o["tool"] for o in row.get("observed", [])}
    problems = []
    if row["verdict"] != "fail":
        problems.append("a tool returning 'ignore all previous instructions' "
                        "was not caught: output.hygiene = {}"
                        .format(row["verdict"]))
    for want in ("lookup", "conceal"):
        if want not in named:
            problems.append("{} returned a payload and was not named".format(want))
    # The control. A scanner that flags ordinary prose is one nobody keeps, and
    # a finding from it would mean nothing.
    if "honest" in named:
        problems.append("honest returns plain prose and was flagged; the "
                        "scanner is producing noise, not findings")
    if not problems:
        print("   payload caught in {}, and plain prose left alone"
              .format(", ".join(sorted(named))))
    return problems


def _check_claims(python, args):
    """A broken promise must be caught; a server that promised nothing must not.

    The second half is the whole safeguard. This names real projects using
    their own marketing text, so a check that manufactures a contradiction
    against a server which never made a promise is not a weaker finding — it
    is an accusation, and the second fixture exists to stop one shipping.
    """
    problems = []
    for fixture, expect in (("hypocriteserver", True), ("leakserver", False)):
        script = os.path.join(ROOT, "seeded", fixture + ".py")
        inner = _parser().parse_args(["verify", "--command",
                                      python + " " + script])
        inner.python, inner.at = python, args.at
        try:
            cmd_verify(inner)
        except SystemExit:
            pass
        report = os.path.join(ROOT, "reports", fixture + ".py.report.json")
        if not os.path.exists(report):
            problems.append("{} produced no report".format(fixture))
            continue
        with open(report, encoding="utf-8") as fh:
            rep = json.load(fh)
        conflicts = rep.get("claimContradictions") or []
        if expect and not conflicts:
            problems.append(
                "{} promises local-only in its own instructions and contacted "
                "a host, and no contradiction was reported".format(fixture))
        if expect and conflicts and not (conflicts[0].get("quote") or "").strip():
            problems.append("a contradiction was reported without quoting the "
                            "words it rests on")
        if not expect and conflicts:
            problems.append(
                "{} makes network calls but promises NOTHING, and {} "
                "contradiction(s) were invented against it"
                .format(fixture, len(conflicts)))
    if not problems:
        print("   broken promise caught in its own words; a server that "
              "promised nothing was left alone")
    return problems


def _check_container_runner():
    """The container path must hold together without Docker. [] = ok.

    Everything about ContainerRunner is invisible on a machine with no Docker,
    so a plain AttributeError inside it reaches CI and then a whole corpus run
    before anyone notices. That is not hypothetical: `self.tag` was referenced
    and never assigned, and seven servers came back as `error` after a full
    sweep because of one missing line. None of the checks below need a daemon,
    and any of them would have caught it in about a second.
    """
    import runner as runner_mod
    problems = []
    try:
        r = runner_mod.make("container", image="x:y", tag="-t1", routed=True)
    except Exception as exc:
        return ["ContainerRunner will not even construct: {}: {}".format(
            type(exc).__name__, exc)]

    for attribute in ("tag", "image", "network", "outside", "proxy_name"):
        if not hasattr(r, attribute):
            problems.append("ContainerRunner has no .{} — something builds a "
                            "name out of it".format(attribute))
    if getattr(r, "enforcement", None) != "contained":
        problems.append("a container runner must report enforcement "
                        "'contained', got {!r}".format(
                            getattr(r, "enforcement", None)))
    try:
        if r.collect_writes() != []:
            problems.append("collect_writes invented writes with no container")
    except Exception as exc:
        problems.append("collect_writes raises without Docker: {}: {}".format(
            type(exc).__name__, exc))
    try:
        r._docker("version")
    except Exception as exc:
        problems.append("a docker call raises instead of reporting failure: "
                        "{}: {}".format(type(exc).__name__, exc))
    try:
        runner_mod.make("nonsense")
        problems.append("make() accepted an unknown runner kind rather than "
                        "refusing")
    except ValueError:
        pass
    except Exception as exc:
        problems.append("make() raised {} for an unknown kind; it should "
                        "refuse with ValueError".format(type(exc).__name__))

    if not problems:
        print("   container runner holds together with no Docker present")
    return problems


def _check_declarations():
    """Validate every declaration this repository ships. [] means good."""
    import jsonschema
    with open(SCHEMA, encoding="utf-8") as fh:
        schema = json.load(fh)
    files = sorted(
        glob.glob(os.path.join(ROOT, "declarations", "**",
                               "*.declaration.json"), recursive=True)
        + glob.glob(os.path.join(ROOT, "seeded", "*.declaration.json")))
    problems = []
    for path in files:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        try:
            jsonschema.validate(doc, schema)
        except jsonschema.ValidationError as exc:
            problems.append("{}: {}".format(os.path.relpath(path, ROOT),
                                            str(exc).splitlines()[0][:90]))
    # The prose spec and the machine schema must list the same invariant
    # types. `no-data-egress` was implemented, used by a fixture, absent from
    # the schema and absent from the spec table -- three documents describing
    # three different programs. Whoever reimplements this reads the prose.
    doc_path = os.path.join(ROOT, "spec", "DECLARATION-DRAFT.md")
    if os.path.exists(doc_path):
        with open(doc_path, encoding="utf-8") as fh:
            doc = fh.read()
        documented = set(re.findall(r"^\| `([a-z-]+)` \|", doc, re.M))
        declared = set(_invariant_type_enum(schema))
        for missing in sorted(declared - documented):
            problems.append("{} is in the schema and not in the spec table"
                            .format(missing))
        for extra in sorted(documented - declared):
            problems.append("{} is in the spec table and not in the schema"
                            .format(extra))
        if not problems:
            print("   spec and schema agree on {} invariant type(s)"
                  .format(len(declared)))

    if not problems:
        print("   {} declarations checked, all valid".format(len(files)))
    return problems


def _invariant_type_enum(node):
    """The invariant-type enum, wherever the schema keeps it."""
    if isinstance(node, dict):
        if "no-network" in (node.get("enum") or []):
            return node["enum"]
        for value in node.values():
            found = _invariant_type_enum(value)
            if found:
                return found
    elif isinstance(node, list):
        for value in node:
            found = _invariant_type_enum(value)
            if found:
                return found
    return None


def _check_status_schema():
    """Validate one status per verdict the builder can reach. [] means good."""
    import jsonschema
    import status as status_mod

    with open(os.path.join(ROOT, "spec", "status.schema.json"),
              encoding="utf-8") as fh:
        schema = json.load(fh)

    def _one(slug, registry_entry=None):
        rp = os.path.join(ROOT, "receipts", slug + ".receipt.jsonl")
        ap = os.path.join(ROOT, "receipts", slug + ".anchor.json")
        if not (os.path.exists(rp) and os.path.exists(ap)):
            return None
        with open(rp, encoding="utf-8") as fh:
            lines = fh.readlines()
        with open(ap, encoding="utf-8") as fh:
            anchor = json.load(fh)
        return status_mod.build(lines, anchor, registry_entry=registry_entry)

    cases = [("certivl", None), ("malserver", None), ("silentserver", None),
             ("certivl", {"state": "revoked", "key": "k",
                          "revocationReason": "test"}),
             ("certivl", {"state": "expired", "key": "k",
                          "expiresAt": "2026-01-01T00:00:00+00:00"})]
    problems, seen = [], set()
    for slug, entry in cases:
        st = _one(slug, entry)
        if st is None:
            continue
        seen.add(st["verdict"])
        try:
            jsonschema.validate(st, schema)
        except jsonschema.ValidationError as exc:
            problems.append("{} -> {}: {}".format(slug, st["verdict"],
                                                  str(exc).splitlines()[0]))
    if not problems:
        print("   {} verdicts checked, all valid: {}".format(
            len(seen), ", ".join(sorted(seen))))
    return problems


def _parser():
    ap = argparse.ArgumentParser(prog="saydo", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list").set_defaults(fn=cmd_list)

    v = sub.add_parser("verify")
    v.add_argument("name", nargs="?",
                   help="a server from `saydo list`, or omit and use "
                        "--command/--npm/--pypi to verify anything")
    v.add_argument("--command",
                   help="the command that starts any MCP server over stdio, "
                        "as one quoted string: --command \"python srv.py\"")
    v.add_argument("--npm", help="verify an npm-published MCP server")
    v.add_argument("--pypi", help="verify a PyPI-published MCP server")
    v.add_argument("--declaration",
                   help="the author's declaration; without one a conservative "
                        "declaration is inferred and tested")
    v.add_argument("--runner", default="local",
                   choices=["local", "container"],
                   help="'container' runs the server in the sandbox")
    v.add_argument("--image", help="container image for --runner container")
    v.add_argument("--routed", action="store_true",
                   help="record bare-IP attempts in any language")
    v.add_argument("--sandbox", action="store_true",
                   help="build a throwaway container for this package and run "
                        "it there: no route out except SayDo's proxy, "
                        "read-only filesystem, no capabilities. Use this for "
                        "anything you did not write.")
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

    pub = sub.add_parser("publish", help="record a receipt in the registry")
    pub.add_argument("name")
    pub.add_argument("--at")
    pub.set_defaults(fn=cmd_publish)

    rev = sub.add_parser("revoke", help="withdraw a claim; a later passing "
                                        "receipt will not lift it")
    rev.add_argument("key", help="the subject purl, as shown by `saydo registry`")
    rev.add_argument("reason")
    rev.set_defaults(fn=cmd_revoke)

    sub.add_parser("registry", help="what SayDo currently says, and until when"
                   ).set_defaults(fn=cmd_registry)

    d = sub.add_parser("declare", help="draft a declaration you can sign, "
                                       "from a run that already happened")
    d.add_argument("name")
    d.add_argument("-o", "--out")
    d.set_defaults(fn=cmd_declare)

    s = sub.add_parser("selfcheck")
    s.add_argument("--python")
    s.add_argument("--at", default="1970-01-01T00:00:00Z")
    s.set_defaults(fn=cmd_selfcheck)
    return ap


def main():
    args = _parser().parse_args()
    raise SystemExit(args.fn(args) or 0)


if __name__ == "__main__":
    main()
