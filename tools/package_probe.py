"""Watch a package do what it does when you merely install or import it.

Nothing here knows what MCP is. The observation stack -- the audit hook, the
recording proxy, the sandbox, the receipts -- was never MCP-specific; only the
DRIVER was, the part that knows how to make a program do work so there is
something to watch. MCP got used because it hands you a machine-readable list
of what a program can do and how to call it, which makes exercising code you
did not write automatable.

Installing and importing need no driver at all. The exercise IS the install,
or the import, and it needs no credential either -- which is the wall the MCP
corpus hit. `pip install X` and `import X` are things a person does hundreds
of times a week, usually while assuming neither runs anything interesting.
Both run arbitrary code the package chose.

Two questions, both general:

    import    does merely importing this reach the network, spawn a process,
              or write outside its own directory?
    install   does installing it run code the package shipped for that
              purpose, and what does that code do?

BASELINE SUBTRACTION, AND HOW MUCH IT ACTUALLY DOES. Every probe runs twice --
once doing nothing, once doing the thing -- and reports the difference. This
file first claimed that was the mechanism, on the reasoning that an
interpreter opens hundreds of files before reaching your code. It does, and
almost none of them are recorded: the monitor logs files opened for WRITING,
not for reading, so a bare interpreter produces about one event and the
subtraction removes about one event.

It is kept because it costs one process and would matter immediately if the
monitor ever started recording reads. It is not what makes this work, and the
claim that it was survived until a gate was written to check it and could not
be made to fail.

WHAT THIS IS NOT. An audit hook observes the Python runtime, not the kernel.
A native extension calling the OS directly walks past it. This catches
telemetry, accidents, and ordinary misbehaviour; it is not a sandbox, and a
package that comes back quiet has been shown quiet under observation, not
proven safe.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
BOOT = os.path.join(HERE, "monitor_boot")

#: Event kinds that mean the package reached outside itself. `open` is
#: deliberately absent: an import reads files by definition, and counting that
#: would drown the signal in the interpreter's own noise.
REACHED_OUT = ("socket.connect", "socket.getaddrinfo", "socket.sendto",
               "subprocess.Popen", "os.system", "os.exec", "os.spawn",
               "os.posix_spawn")

WROTE = ("os.remove", "os.rename", "os.mkdir", "os.rmdir", "os.truncate",
         "os.link", "os.symlink", "shutil.rmtree", "shutil.copyfile",
         "shutil.move")


def _run_watched(python, code, timeout=120, extra_env=None):
    """Run one snippet under the audit hook and return the events it caused."""
    log = tempfile.NamedTemporaryFile(delete=False, suffix=".jsonl")
    log.close()
    env = dict(os.environ)
    prior = env.get("PYTHONPATH")
    env["PYTHONPATH"] = BOOT + (os.pathsep + prior if prior else "")
    env["SAYDO_MONITOR_LOG"] = log.name
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    if extra_env:
        env.update(extra_env)
    try:
        proc = subprocess.run([python, "-c", code], env=env, timeout=timeout,
                              capture_output=True, text=True)
    except subprocess.TimeoutExpired:
        return [], "timed out"
    events = []
    try:
        with open(log.name, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except ValueError:
                    continue
    finally:
        try:
            os.unlink(log.name)
        except OSError:
            pass
    return events, (proc.stderr or "").strip()[-400:]


def _signature(event):
    """What an event is, ignoring when it happened."""
    return (event.get("event"), json.dumps(event.get("args"))[:200])


def probe_import(module, python=None, timeout=120):
    """What importing this module does that starting the interpreter does not.

    The baseline is the same interpreter importing nothing. Everything it does
    on its own -- reading its standard library, resolving its own paths -- is
    subtracted, so what is left was caused by this module.
    """
    python = python or sys.executable
    base, _ = _run_watched(python, "pass", timeout)
    seen = {_signature(e) for e in base}
    after, stderr = _run_watched(
        python, "import {}".format(module), timeout)

    caused = [e for e in after if _signature(e) not in seen]
    network = [e for e in caused if e.get("event") in REACHED_OUT
               and e.get("event", "").startswith("socket")]
    spawned = [e for e in caused if e.get("event") in REACHED_OUT
               and not e.get("event", "").startswith("socket")]
    wrote = [e for e in caused if e.get("event") in WROTE]

    return {
        "module": module,
        "baselineEvents": len(base),
        "eventsCaused": len(caused),
        "network": [e.get("args") for e in network][:20],
        "subprocess": [e.get("args") for e in spawned][:20],
        "writes": [e.get("args") for e in wrote][:20],
        "importFailed": bool(stderr and "Error" in stderr),
        "stderr": stderr if stderr else None,
    }


def verdicts_for(probe):
    """Three-valued, matching the harness: pass / fail / not-covered.

    An import that FAILED establishes nothing. A module that could not be
    imported has not been shown to be quiet at import; it has not been shown
    anything, and counting it as clean is how a survey ends up reporting the
    packages it could not test as the healthy ones.
    """
    out = []

    def add(invariant, bad, detail):
        if probe["importFailed"]:
            out.append({"id": invariant, "verdict": "not-covered",
                        "evidence": "the import failed, so nothing about its "
                                    "behaviour was established"})
        elif bad:
            out.append({"id": invariant, "verdict": "fail", "evidence": detail})
        else:
            out.append({"id": invariant, "verdict": "pass",
                        "evidence": "none observed, over a subtracted baseline "
                                    "of {} interpreter events"
                                    .format(probe["baselineEvents"])})

    add("import.no-network", probe["network"],
        "importing it reached the network: {}".format(probe["network"][:3]))
    add("import.no-subprocess", probe["subprocess"],
        "importing it spawned a process: {}".format(probe["subprocess"][:3]))
    add("import.no-writes", probe["writes"],
        "importing it modified files: {}".format(probe["writes"][:3]))
    return out


def check(python=None):
    """Problems with this probe, for the selfcheck gate. [] = good.

    A detector that only ever says clean is worse than no detector: it
    launders an absence of measurement into a clean bill of health. The
    fixture exists so that this file cannot pass without catching something.
    """
    python = python or sys.executable
    problems = []
    seeded = os.path.join(os.path.dirname(HERE), "seeded")

    # 1. It must catch a module that acts at import. All three channels,
    #    because a probe that sees network but not subprocesses would report
    #    a package that shells out as quiet.
    env_path = os.environ.get("PYTHONPATH")
    os.environ["PYTHONPATH"] = seeded + (
        os.pathsep + env_path if env_path else "")
    try:
        loud = probe_import("importphone", python)
    finally:
        if env_path is None:
            os.environ.pop("PYTHONPATH", None)
        else:
            os.environ["PYTHONPATH"] = env_path
    if loud["importFailed"]:
        problems.append("the fixture that acts at import could not be "
                        "imported, so this gate tested nothing")
    else:
        for channel in ("network", "subprocess", "writes"):
            if not loud[channel]:
                problems.append(
                    "a module that reaches the network, spawns a process and "
                    "writes a file at import was not caught on {}"
                    .format(channel))

    # 2. It must leave a quiet module alone. Every import reads files and
    #    the interpreter does plenty on its own; without baseline subtraction
    #    that noise becomes a finding about every package measured.
    quiet = probe_import("json", python)
    # The subtraction itself, not just its effect on the three channels. Those
    # exclude `open`, which is where nearly all interpreter noise lives, so
    # they stay clean even when subtraction is broken -- and this file claims
    # subtraction is load-bearing. The claim has to be checked where it bites:
    # the count of events attributed to the package.
    if quiet["eventsCaused"] > 5:
        problems.append(
            "importing a stdlib module was credited with {} events, so the "
            "interpreter's own startup is being attributed to the package "
            "and every count this produces is inflated"
            .format(quiet["eventsCaused"]))
    for channel in ("network", "subprocess", "writes"):
        if quiet[channel]:
            problems.append(
                "importing a stdlib module was reported as {} activity, so "
                "the interpreter's own noise is being attributed to packages"
                .format(channel))

    # 3. A package that could not be imported has not been shown to be quiet.
    #    Counting it as a pass is how a survey reports the packages it failed
    #    to test as the healthy ones.
    missing = probe_import("saydo_no_such_module_exists", python)
    if not missing["importFailed"]:
        problems.append("a module that does not exist did not register as a "
                        "failed import")
    else:
        for verdict in verdicts_for(missing):
            if verdict["verdict"] == "pass":
                problems.append(
                    "{} passed for a package that could not even be imported"
                    .format(verdict["id"]))
    return problems


def main():
    argv = sys.argv[1:]
    if argv and argv[0] == "--check":
        found = check()
        for line in found:
            print("  " + line)
        raise SystemExit(1 if found else 0)
    if not argv:
        raise SystemExit(__doc__)
    for module in argv:
        probe = probe_import(module)
        print("\n{}".format(module))
        if probe["importFailed"]:
            print("   could not be imported -- nothing established")
            print("   {}".format((probe["stderr"] or "").splitlines()[-1][:100]))
            continue
        print("   {} events caused beyond a baseline of {}"
              .format(probe["eventsCaused"], probe["baselineEvents"]))
        for verdict in verdicts_for(probe):
            mark = {"pass": " ok ", "fail": "FAIL", "not-covered": "----"}[
                verdict["verdict"]]
            print("   [{}] {:<22} {}".format(mark, verdict["id"],
                                             verdict["evidence"][:90]))


if __name__ == "__main__":
    main()
