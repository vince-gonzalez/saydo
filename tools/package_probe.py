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
import secrets
import shutil
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

#: Paths whose CONTENTS are credentials. A package reading one of these while
#: you merely import it is the finding this whole project was looking for, and
#: it is the thing static analysis is worst at: the path can be assembled at
#: runtime, read through a native extension, or fetched from a config value,
#: and source inspection sees none of that. Running the code sees all of it.
SECRET_PATHS = (
    ".ssh", "id_rsa", "id_ed25519", "id_ecdsa", "authorized_keys",
    ".npmrc", ".pypirc", ".netrc", ".git-credentials",
    ".aws", ".azure", ".kube", "docker/config", "docker\\config",
    ".gnupg", "keyring", "keychain", "credentials.json",
    "client_secret", "service-account", "token.json",
    ".env", "secrets.yaml", "secrets.yml", "cookies.sqlite",
    "Login Data", "Cookies", "wallet.dat", ".bash_history",
)

#: Read constantly by ordinary code and never interesting.
SECRET_NOISE = ("site-packages", "__pycache__", "/lib/", '\\lib\\',
                "dist-info", "egg-info", "node_modules")


def secret_reads(events):
    """Reads of paths that hold credentials, with the interpreter's own noise
    removed. Case-insensitive: Windows paths vary and a miss here is a miss of
    the only channel that matters."""
    out = []
    for e in events:
        if e.get("event") != "open" or e.get("intent") != "read":
            continue
        path = str(e.get("path") or "")
        low = path.lower()
        if any(n.lower() in low for n in SECRET_NOISE):
            continue
        for marker in SECRET_PATHS:
            if marker.lower() in low:
                out.append({"path": path, "matched": marker})
                break
    return out


WROTE = ("os.remove", "os.rename", "os.mkdir", "os.rmdir", "os.truncate",
         "os.link", "os.symlink", "shutil.rmtree", "shutil.copyfile",
         "shutil.move")


#: Files planted in the isolated home. Each carries a unique marker, so a
#: value found later in egress names the run that planted it -- a decoy is a
#: canary as well as a tripwire.
#: Files planted in the isolated home, written as LINE LISTS so no escape
#: sequence appears in this source at all. Each carries a unique marker, so a
#: value found later in captured egress names the run that planted it -- a
#: decoy is a canary as well as a tripwire.
DECOYS = {
    ".npmrc": ["//registry.npmjs.org/:_authToken=SAYDO-DECOY-{m}"],
    ".netrc": ["machine example.com login saydo password SAYDO-DECOY-{m}"],
    ".pypirc": ["[pypi]", "username = __token__",
                "password = SAYDO-DECOY-{m}"],
    ".env": ["API_KEY=SAYDO-DECOY-{m}", "DATABASE_URL=postgres://x/y"],
    ".git-credentials": ["https://saydo:SAYDO-DECOY-{m}@github.com"],
    ".ssh/id_rsa": ["-----BEGIN OPENSSH PRIVATE KEY-----",
                    "SAYDO-DECOY-{m}", "-----END OPENSSH PRIVATE KEY-----"],
    ".aws/credentials": ["[default]",
                         "aws_secret_access_key = SAYDO-DECOY-{m}"],
}


def _isolated_home(marker):
    """A throwaway home directory, furnished with decoy credentials.

    Two problems, one answer. Redirecting HOME makes first-run state fresh for
    anything that initialises in a config or cache directory rather than temp,
    which a single probe otherwise sees once and never again. And it means the
    detector never has to read -- or write -- the operator's real credential
    files to find out whether a package reads credential files.

    The decoys are what a thief would want and are worth nothing. Each carries
    a marker, so the same value turning up in captured egress is not an
    inference about intent, it is the file leaving.
    """
    root = tempfile.mkdtemp(prefix="saydo-home-")
    for rel, body in DECOYS.items():
        path = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(chr(10).join(l.format(m=marker) for l in body)
                     + chr(10))
    return root


def _run_watched(python, code, timeout=120, extra_env=None):
    """Run one snippet under the audit hook and return the events it caused."""
    log = tempfile.NamedTemporaryFile(delete=False, suffix=".jsonl")
    log.close()
    env = dict(os.environ)
    prior = env.get("PYTHONPATH")
    env["PYTHONPATH"] = BOOT + (os.pathsep + prior if prior else "")
    env["SAYDO_MONITOR_LOG"] = log.name
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    # A FRESH temp directory per probe. Dynamic observation sees a one-time
    # side effect exactly once: adodbapi created a cache directory on its
    # first import and every run after that found it already there and did
    # nothing, so the probe reported clean for behaviour it had itself
    # triggered. Anything a package caches, seeds or drops on first use lands
    # here, and here is empty every time.
    scratch = tempfile.mkdtemp(prefix="saydo-probe-")
    for var in ("TEMP", "TMP", "TMPDIR"):
        env[var] = scratch
    # An isolated HOME as well, furnished with decoys. Resetting temp alone
    # left every package that initialises in a config or cache directory
    # looking clean on its second run for ever after.
    home = _isolated_home(secrets.token_hex(4))
    for var in ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
                "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME"):
        env[var] = home
    env["HOMEDRIVE"], env["HOMEPATH"] = home[:2], home[2:]
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
        shutil.rmtree(scratch, ignore_errors=True)
        shutil.rmtree(home, ignore_errors=True)
    return events, (proc.stderr or "").strip()[-400:]


def _signature(event):
    """What an event is, ignoring when it happened.

    `open` rows carry `path` and `intent`, never `args`. Keying only on args
    gave every open in the process the identical signature, so a single open
    in the baseline subtracted EVERY open the package made -- including a read
    of ~/.npmrc that the monitor had captured correctly and handed over. The
    observation was right; the bookkeeping deleted it.
    """
    kind = event.get("event")
    if kind == "open":
        return (kind, event.get("intent"), str(event.get("path") or "")[:200])
    return (kind, json.dumps(event.get("args"))[:200])


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
    secrets = secret_reads(caused)

    return {
        "module": module,
        "baselineEvents": len(base),
        "eventsCaused": len(caused),
        "network": [e.get("args") for e in network][:20],
        "subprocess": [e.get("args") for e in spawned][:20],
        "writes": [e.get("args") for e in wrote][:20],
        "secretReads": secrets[:20],
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
    # Last because it is the one that matters. A package that reads a
    # credential file while you merely import it has done the thing every
    # supply-chain scanner exists to catch, and it did it in a way source
    # inspection can miss entirely.
    add("import.no-credential-reads", probe.get("secretReads"),
        "importing it read credentials: {}".format(
            [s["path"] for s in (probe.get("secretReads") or [])][:3]))
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

    # 1b. Credential reads: the channel that matters, and the one most
    #     likely to rot silently, because it depends on the isolated home
    #     being built AND the baseline signature keeping open events apart.
    loud2 = probe_import("credreader", python)
    if loud2["importFailed"]:
        problems.append("the credential-reading fixture could not be "
                        "imported, so that channel tested nothing")
    else:
        hits = loud2.get("secretReads") or []
        if not hits:
            problems.append(
                "a module that reads ~/.npmrc at import was not caught; the "
                "path is assembled at runtime, which is exactly the case "
                "source inspection misses")
        elif not any("npmrc" in str(h.get("path", "")).lower()
                     for h in hits):
            problems.append("a credential read was reported without naming "
                            "the file it read")
        for h in hits:
            if "saydo-home-" not in str(h.get("path", "")):
                problems.append(
                    "the fixture read {!r}, which is OUTSIDE the isolated "
                    "home -- the probe is touching real credential files"
                    .format(str(h.get("path"))[:60]))

    # 1c. The isolated home must be furnished and self-contained. An empty
    #     home silently disarms the whole channel: nothing to read means
    #     nothing detected, and every package looks clean.
    home = _isolated_home("testmarker")
    try:
        for rel in DECOYS:
            if not os.path.exists(os.path.join(home, *rel.split("/"))):
                problems.append("decoy {!r} was not planted".format(rel))
        with open(os.path.join(home, ".npmrc"), encoding="utf-8") as fh:
            body = fh.read()
        if "testmarker" not in body:
            problems.append("a decoy carries no run marker, so a value found "
                            "in egress could not be tied to the run that "
                            "planted it")
        if os.path.realpath(home) == os.path.realpath(
                os.path.expanduser("~")):
            problems.append("the isolated home IS the real home")
    finally:
        shutil.rmtree(home, ignore_errors=True)

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
