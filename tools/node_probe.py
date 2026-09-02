"""The import probe, for Node. Same instrument, the ecosystem that gets attacked.

Python was where this was built; npm is where supply-chain compromise actually
happens -- postinstall scripts, typosquats, dependency confusion. The monitor
for it already existed (node_monitor.js, loaded with --require before the
package's own code) and emits the SAME event names the Python hook does, so
everything downstream -- credential-path matching, decoy homes, the egress
loop -- is reused unchanged. Only the launch differs: node -e require(x) in
place of python -c import x.

Reads were not observed on the Node side until now, which meant the credential
channel -- the one that matters -- was blind there. That is fixed in the
monitor; this driver consumes it.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import package_probe as P

MONITOR = os.path.join(HERE, "monitor_boot", "node_monitor.js")


def _events_from_stderr(stderr):
    out = []
    for line in (stderr or "").splitlines():
        if line.startswith("@@SAYDO@@ "):
            try:
                out.append(json.loads(line[len("@@SAYDO@@ "):]))
            except ValueError:
                continue
    return out


def probe_require(package, node="node", timeout=40):
    """require() a package under the Node monitor, in a decoy home.

    The package is required, not installed here -- the caller installs it into
    a scratch prefix first (the sweep does this per batch). What is measured is
    what the module body does when loaded, which is what runs on the first
    require of any dependency in a project.
    """
    marker = "SAYDO-DECOY-" + os.urandom(4).hex()
    home = P._isolated_home(marker)
    scratch = tempfile.mkdtemp(prefix="saydo-node-")
    # A path to a local .js file must be made absolute: node resolves a
    # relative require() against its own cwd, not the caller's, so a fixture
    # given as "seeded/x.js" would silently not be found and the run would
    # look clean. A bare package name (the real case) is left untouched.
    target = package
    if package.endswith(".js") or os.path.sep in package or "/" in package:
        cand = os.path.abspath(package)
        if os.path.exists(cand):
            target = cand.replace("\\", "/")
    try:
        env = dict(os.environ)
        for var in ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
                    "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME"):
            env[var] = home
        env["HOMEDRIVE"], env["HOMEPATH"] = home[:2], home[2:]
        env["TEMP"] = env["TMP"] = env["TMPDIR"] = scratch
        expr = "require({})".format(json.dumps(target))
        try:
            out = subprocess.run(
                [node, "--require", MONITOR, "-e", expr],
                env=env, timeout=timeout, capture_output=True, text=True)
            stderr, blocked = out.stderr or "", False
        except subprocess.TimeoutExpired as exc:
            raw = exc.stderr or b""
            stderr = raw.decode("utf-8", "replace") if isinstance(raw, bytes) \
                else (raw or "")
            blocked = True

        events = _events_from_stderr(stderr)
        loaded = any(e.get("event") == "monitor.ready" for e in events) \
            or blocked
        caused = [e for e in events if e.get("event") != "monitor.ready"]
        net = [e for e in caused if e.get("event", "").startswith("socket")]
        proc = [e for e in caused if e.get("event") == "subprocess.Popen"]
        writes = [e for e in caused
                  if e.get("event") == "open" and e.get("intent") == "write"]
        secrets = P.secret_reads(caused)
        return {"package": package, "loaded": loaded, "blocked": blocked,
                "network": [e.get("args") for e in net][:20],
                "subprocess": [e.get("args") for e in proc][:20],
                "writes": [e.get("path") for e in writes][:20],
                "secretReads": secrets[:20]}
    finally:
        shutil.rmtree(home, ignore_errors=True)
        shutil.rmtree(scratch, ignore_errors=True)


def check(node="node"):
    """A Node module that reads a decoy credential must be caught, and a quiet
    one left alone. Needs node on PATH; skips cleanly if absent."""
    if not shutil.which(node):
        print("   (node not on PATH; Node probe self-test skipped)")
        return []
    problems = []
    fixture = os.path.join(os.path.dirname(HERE), "seeded", "node_credreader.js")

    loud = probe_require(fixture, node)
    if not loud["loaded"]:
        problems.append("the Node credential fixture did not load, so nothing "
                        "was tested")
    elif not loud["secretReads"]:
        problems.append("a Node module that reads ~/.npmrc at require was not "
                        "caught; the monitor is not observing reads")
    else:
        for h in loud["secretReads"]:
            if "saydo-home-" not in str(h.get("path", "")):
                problems.append("the fixture read outside the isolated home")

    quiet = probe_require(os.path.join(os.path.dirname(HERE), "seeded",
                                       "node_quiet.js"), node)
    if quiet["secretReads"]:
        problems.append("a quiet Node module was reported reading credentials")
    return problems


def main():
    argv = sys.argv[1:]
    if argv and argv[0] == "--check":
        found = check()
        for line in found:
            print("  " + line)
        print("node probe: {}".format(
            "all hold" if not found else "{} PROBLEM(S)".format(len(found))))
        raise SystemExit(1 if found else 0)
    if not argv:
        raise SystemExit(__doc__)
    for package in argv:
        r = probe_require(package)
        if not r["loaded"]:
            print("  {:<24} did not load".format(package)); continue
        tag = "CRED" if r["secretReads"] else (
            "ACT" if (r["network"] or r["subprocess"] or r["writes"]) else "ok")
        print("  {:<5} {:<24} net={} proc={} write={} cred={}".format(
            tag, package, len(r["network"]), len(r["subprocess"]),
            len(r["writes"]), len(r["secretReads"])))


if __name__ == "__main__":
    main()
