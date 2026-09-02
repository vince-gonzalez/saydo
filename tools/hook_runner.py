"""Run each hooked package's install script for real and record what it does.

Not the manifest, not the source -- the script, executed under the monitor in
a decoy home. Every hooked package from the survey, one at a time, with a hard
per-package budget so one hang cannot eat the run.

The output is a table of what actually happened: which scripts self-disabled,
which contacted hosts, which read the decoy credentials, which wrote outside
their own directory. A package that reads a decoy credential on a default run
is the finding that needs no interpretation.

Scope, stated plainly: this runs node-driven hooks (`node script` and
`node -e`). `npx only-allow pnpm` and toolchain builds are recorded as their
kind and NOT run -- only-allow merely aborts a non-pnpm install, and a build
needs a compiler. The interesting population is the hook that invokes node on
a script the package shipped, and that is what is executed.
"""

from __future__ import annotations

import io
import json
import os
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import install_scripts
import package_probe as P

MONITOR = os.path.join(HERE, "monitor_boot", "node_monitor.js")
BUDGET = 45
DQ = chr(34)


def fetch_scripts(name, meta, dest):
    """Download the tarball (never installed) and extract its scripts and any
    .mjs/.cjs/.js it might load. Returns (root, extracted names)."""
    tarball = (meta.get("dist") or {}).get("tarball")
    if not tarball:
        return None, []
    try:
        data = urllib.request.urlopen(tarball, timeout=45).read()
        tf = tarfile.open(fileobj=io.BytesIO(data))
    except Exception as exc:
        return None, ["fetch failed: {}".format(exc)[:80]]
    got = []
    for member in tf.getmembers():
        if not member.isfile():
            continue
        n = member.name
        low = n.lower()
        keep = ("/scripts/" in low or low.endswith("package.json")
                or (low.endswith((".mjs", ".cjs", ".js"))
                    and "/node_modules/" not in low))
        if not keep:
            continue
        rel = n.split("/", 1)[1] if "/" in n else n
        out = os.path.join(dest, rel)
        try:
            os.makedirs(os.path.dirname(out), exist_ok=True)
            with open(out, "wb") as fh:
                fh.write(tf.extractfile(member).read())
            got.append(rel)
        except Exception:
            pass
    return dest, got


def hook_command(meta):
    scripts = (meta or {}).get("scripts") or {}
    for hook in ("preinstall", "install", "postinstall"):
        body = scripts.get(hook)
        if body:
            return hook, body
    return None, None


def run_one(name, timeout=BUDGET):
    meta = install_scripts.manifest(name)
    if not meta:
        return {"name": name, "outcome": "no-manifest"}
    hook, body = hook_command(meta)
    if not hook:
        return {"name": name, "outcome": "no-hook"}

    pkgdir = tempfile.mkdtemp(prefix="saydo-pkg-")
    home = P._isolated_home("m" + os.urandom(3).hex())
    try:
        root, _ = fetch_scripts(name, meta, os.path.join(pkgdir, "package"))
        if not root:
            return {"name": name, "outcome": "no-tarball", "hook": hook}

        parts = shlex.split(body, posix=False)
        if not (parts and parts[0] == "node"):
            return {"name": name, "outcome": "not-node-hook",
                    "hook": hook, "body": body[:80]}

        env = dict(os.environ)
        for v in ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
                  "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME"):
            env[v] = home
        env["HOMEDRIVE"], env["HOMEPATH"] = home[:2], home[2:]
        env["TEMP"] = env["TMP"] = env["TMPDIR"] = home
        env["INIT_CWD"] = home

        if "-e" in parts:
            code = parts[parts.index("-e") + 1].strip(DQ)
            argv = ["node", "--require", MONITOR, "-e", code]
        else:
            script = parts[1].strip(DQ).replace(chr(92), "/")
            local = os.path.join(root, *script.split("/"))
            if not os.path.exists(local):
                return {"name": name, "outcome": "script-missing",
                        "hook": hook, "wanted": script}
            argv = ["node", "--require", MONITOR, os.path.abspath(local)]

        started = time.time()
        blocked = False
        try:
            out = subprocess.run(argv, env=env, cwd=home, timeout=timeout,
                                 capture_output=True)
            stderr = (out.stderr or b"").decode("utf-8", "replace")
        except subprocess.TimeoutExpired as exc:
            raw = exc.stderr or b""
            stderr = raw.decode("utf-8", "replace") if isinstance(raw, bytes) \
                else (raw or "")
            blocked = True

        ev = []
        for line in stderr.splitlines():
            if line.startswith("@@SAYDO@@ "):
                try:
                    ev.append(json.loads(line[len("@@SAYDO@@ "):]))
                except ValueError:
                    pass
        net = sorted({str((e.get("args") or [""])[0])
                      for e in ev
                      if e.get("event") == "socket.getaddrinfo"})
        net = [h for h in net if h and h != "None"]
        writes = [e.get("path") for e in ev
                  if e.get("event") == "open" and e.get("intent") == "write"
                  and "saydo-home" in str(e.get("path", ""))]
        creds = P.secret_reads(ev)
        acted = bool(net or writes or creds)
        skipped = ("skip probe" in stderr.lower()) or (
            not acted and any(e.get("event") == "monitor.ready" for e in ev))
        return {
            "name": name, "outcome": "ran", "hook": hook, "blocked": blocked,
            "selfDisabled": skipped and not acted,
            "network": net, "wroteHome": writes,
            "credentialReads": [c["path"] for c in creds],
            "seconds": round(time.time() - started, 1),
        }
    finally:
        shutil.rmtree(pkgdir, ignore_errors=True)
        shutil.rmtree(home, ignore_errors=True)


def main():
    if len(sys.argv) > 1:
        names = json.load(io.open(sys.argv[1], encoding="utf-8"))
    else:
        names = json.load(io.open(
            os.path.join(os.path.dirname(HERE), "corpus", "hooked-names.json"),
            encoding="utf-8"))
    out_path = sys.argv[2] if len(sys.argv) > 2 else None

    results = []
    print("running {} hooked packages, real scripts, decoy home\n"
          .format(len(names)), flush=True)
    for i, name in enumerate(names):
        try:
            r = run_one(name)
        except Exception as exc:
            r = {"name": name, "outcome": "error", "error": str(exc)[:100]}
        results.append(r)
        if r.get("outcome") == "ran":
            marks = []
            if r["credentialReads"]:
                marks.append("CRED:{}".format(len(r["credentialReads"])))
            if r["network"]:
                marks.append("net:{}".format(len(r["network"])))
            if r["wroteHome"]:
                marks.append("wrote:{}".format(len(r["wroteHome"])))
            if r["selfDisabled"]:
                marks.append("self-disabled")
            state = " ".join(marks) or "quiet"
            print("  [{:>2}/{}] {:<40} {}"
                  .format(i + 1, len(names), name[:40], state), flush=True)
        else:
            print("  [{:>2}/{}] {:<40} ({})"
                  .format(i + 1, len(names), name[:40], r.get("outcome")),
                  flush=True)
        if out_path:
            io.open(out_path, "w", encoding="utf-8").write(
                json.dumps(results, indent=1))

    ran = [r for r in results if r.get("outcome") == "ran"]
    print("\n=== summary ===")
    print("ran:               {}".format(len(ran)))
    print("self-disabled:     {}".format(sum(1 for r in ran if r["selfDisabled"])))
    print("contacted a host:  {}".format(sum(1 for r in ran if r["network"])))
    print("wrote in home:     {}".format(sum(1 for r in ran if r["wroteHome"])))
    print("READ A CREDENTIAL: {}".format(sum(1 for r in ran if r["credentialReads"])))
    for r in ran:
        if r["credentialReads"]:
            print("   {}  read {}".format(r["name"], r["credentialReads"]))


if __name__ == "__main__":
    main()
