"""Sweep many third-party MCP servers, one batch at a time, in the sandbox.

Scale changes the shape of the problem. Building an image per server would
cost a minute each and never finish; installing inside the sandbox is
impossible, because the sandbox has no route to a package registry -- that is
the whole point of it. So a batch of packages is baked into ONE image, and
each server in the batch is then run from that image in its own container.

Every server is measured with the counterfactual switched on, so the output is
not "N servers contacted M hosts" but which destinations carry the tool's own
input and which are simply where the tool always calls. That distinction is
the reason to run this at all.

Failure is expected and is data. A package that will not install, will not
start, or answers nothing is recorded as such rather than dropped, because a
corpus that silently discards its failures overstates how healthy the
ecosystem is.

Usage:
    python sweep_scale.py <candidates.json> <batch_index> <batch_size> <out.json>
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import capture_tools
import differential
import harness
import infer_declaration
import plans as plans_mod
import runner as runner_mod

PY_IMAGE = "saydo/batch-py:ci"
NODE_IMAGE = "saydo/batch-node:ci"


def batch_of(candidates, index, size):
    start = index * size
    return candidates[start:start + size]


def write_dockerfiles(batch, out_dir):
    """One image per registry, each carrying the whole batch.

    Installs are best-effort and deliberately non-fatal: a batch must not be
    lost because one package in it is broken, and a package that fails to
    install is recorded later as exactly that.
    """
    py = [c for c in batch if c["registry"] == "pypi"]
    node = [c for c in batch if c["registry"] == "npm"]
    made = {}

    if py:
        specs = " ".join('"{}"'.format(c["name"]) for c in py)
        path = os.path.join(out_dir, "Dockerfile.batch-py")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(
                "FROM python:3.12-slim\n"
                "RUN useradd --create-home --uid 10001 saydo\n"
                "RUN pip install --no-cache-dir mcp==1.29.1 || true\n"
                # One package at a time so a single bad dependency cannot take
                # the batch with it.
                "RUN for p in {}; do pip install --no-cache-dir \"$p\" "
                "|| echo \"SAYDO-INSTALL-FAILED $p\"; done\n"
                "COPY tools/monitor_boot /saydo/monitor_boot\n"
                "ENV PYTHONPATH=/saydo/monitor_boot\n"
                "USER saydo\nWORKDIR /scratch\nENTRYPOINT []\n".format(specs))
        made["pypi"] = (path, PY_IMAGE)

    if node:
        specs = " ".join('"{}"'.format(c["name"]) for c in node)
        path = os.path.join(out_dir, "Dockerfile.batch-node")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(
                "FROM node:22-slim\n"
                "RUN useradd --create-home --uid 10001 saydo\n"
                "RUN for p in {}; do npm install -g --omit=dev \"$p\" "
                "|| echo \"SAYDO-INSTALL-FAILED $p\"; done\n"
                "USER saydo\nWORKDIR /scratch\nENTRYPOINT []\n".format(specs))
        made["npm"] = (path, NODE_IMAGE)

    return made


def build(dockerfile, image):
    out = subprocess.run(
        ["docker", "build", "-f", dockerfile, "-t", image, "."],
        cwd=ROOT, capture_output=True, text=True, timeout=1800)
    return out.returncode == 0, (out.stderr or "")[-400:]


def npm_bins(name, timeout=20):
    """The binaries a package actually declares, from the registry.

    Guessing this is wrong often enough to sink a sweep:
    @aashari/mcp-server-atlassian-jira installs a binary called
    mcp-atlassian-jira, which no rule derived from the package name produces.
    The registry knows the answer, so ask it rather than infer it.
    """
    import urllib.request
    url = "https://registry.npmjs.org/{}/latest".format(
        name.replace("/", "%2f"))
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "saydo/0.1"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            manifest = json.loads(r.read().decode("utf-8", "replace"))
    except Exception:
        return []
    declared = manifest.get("bin")
    if isinstance(declared, dict):
        return list(declared.keys())
    if isinstance(declared, str):
        return [name.split("/")[-1]]
    return []


def image_bins(image):
    """Every executable the built image provides, so a Python package's
    console script can be found by name rather than assumed."""
    out = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "--entrypoint", "sh",
         image, "-c", "ls /usr/local/bin 2>/dev/null"],
        capture_output=True, text=True, timeout=120)
    return set((out.stdout or "").split())


def commands_for(candidate, available=()):
    """In-container commands to try, best evidence first.

    A server that answers none of them is recorded as unstartable, which is a
    finding about how hard this ecosystem is to audit rather than a silent
    omission.
    """
    name = candidate["name"]
    bare = name.split("/")[-1]
    tried = []

    if candidate["registry"] == "npm":
        for b in candidate.get("bins") or npm_bins(name):
            tried.append([b])
        tried.append([bare])
        tried.append(["npx", "-y", name])
        return tried

    # PyPI does not publish console-script names, so match what the image
    # actually installed against the tokens of the package name.
    tokens = [t for t in bare.replace("_", "-").split("-") if len(t) > 2]
    scored = []
    for b in available:
        hits = sum(1 for t in tokens if t in b)
        if hits:
            scored.append((hits, b))
    for _, b in sorted(scored, reverse=True)[:3]:
        tried.append([b])
    tried.append([bare])
    tried.append([bare.replace("_", "-")])
    tried.append(["python", "-m", bare.replace("-", "_")])
    return tried


def measure(candidate, image, available=(), seq=0, timeout=90):
    """Capture, infer, exercise, classify. Never raises."""
    name = candidate["name"]
    record = {"name": name, "registry": candidate["registry"],
              "version": candidate.get("version", ""),
              "description": candidate.get("description", "")}

    # A stable per-server suffix. hash() is salted per process, so using it
    # would give the same server a different network name on every run and
    # make a failure impossible to reproduce.
    the_runner = runner_mod.make("container", image=image,
                                 tag="-b{}".format(seq))

    attempts = commands_for(candidate, available)
    record["tried"] = [" ".join(a) for a in attempts]
    for argv in attempts:
        plan = {"container_argv": list(argv), "exercise": [],
                "call_timeout": 30, "skip_fuzz": True}
        # Capture runs the server directly to read tools/list. It is still
        # inside a container, just without the proxy standing up first.
        probe = ["docker", "run", "--rm", "-i", "--network", "none",
                 "--read-only", "--tmpfs", "/scratch:rw,noexec,nosuid,size=64m,mode=1777",
             "--tmpfs", "/home/saydo:rw,noexec,nosuid,size=32m,mode=1777",
             "-e", "HOME=/home/saydo", "-e", "TMPDIR=/scratch",
             "--cap-drop", "ALL",
                 "--security-opt", "no-new-privileges", "--memory", "512m",
                 "--workdir", "/scratch", image] + argv
        try:
            capture = capture_tools.capture(probe)
        except Exception:
            continue
        if not capture.get("tools"):
            continue

        record["tools"] = [t["name"] for t in capture["tools"]]
        record["server"] = capture.get("server", {})
        declaration = infer_declaration.infer(
            capture, purl="pkg:{}/{}".format(candidate["registry"], name),
            supplier=name)
        # The conservative skeleton always claims no-data-egress, so every
        # server in the corpus gets the counterfactual.
        declaration["invariants"].append(
            {"id": "data.stays-put", "type": "no-data-egress",
             "appliesTo": ["*"]})
        full = plans_mod.synth_plan(capture, argv)
        full["container_argv"] = list(argv)

        try:
            report = harness.run_conformance(name, full, declaration, capture,
                                             sys.executable, runner=the_runner)
        except SystemExit as e:
            record["outcome"] = "harness-refused"
            record["error"] = str(e)[:200]
            return record
        except Exception:
            record["outcome"] = "error"
            record["error"] = traceback.format_exc(limit=2)[-300:]
            return record

        record["outcome"] = "measured"
        record["conformant"] = report["conformant"]
        # `conformant` alone cannot carry this. It means nothing failed, and
        # nothing fails in a run where nothing happened, so a server that
        # declined every call is recorded conformant. `established` counts the
        # invariants about the server's CONDUCT that were demonstrated, and
        # zero is the honest description of most of this corpus.
        record["established"] = report.get("established", 0)
        record["tally"] = report["tally"]
        record["dataFlow"] = report.get("dataFlow", {})
        record["findings"] = [
            {"invariant": v["id"], "type": v["type"],
             "evidence": v["evidence"][:300]}
            for v in report["verdicts"] if v["verdict"] == "fail"]
        # Every verdict with its evidence, not only the failures. Seven servers
        # came back with identical tallies and the record could not say why:
        # working out whether those passes were observations or silence meant
        # re-deriving it from the code. A result that cannot explain itself is
        # not much of a result.
        record["verdicts"] = [
            {"invariant": v["id"], "verdict": v["verdict"],
             "evidence": (v.get("evidence") or "")[:220]}
            for v in report["verdicts"]]
        record["enforcement"] = report.get("enforcement")
        return record

    record["outcome"] = "unstartable"
    record["error"] = "no conventional launch command produced a tools/list"
    # WHY it would not start is the finding. "Unstartable" lumps together a
    # server demanding an API key, a server that crashes, and a launch command
    # we guessed wrong -- three very different facts about the ecosystem, and
    # only one of them is about the ecosystem at all.
    record["diagnosis"] = _diagnose(attempts, image)
    return record


CREDENTIAL_HINTS = ("api_key", "api key", "apikey", "token", "credential",
                    "unauthorized", "authentication", "must be set",
                    "environment variable", "not set", "missing required",
                    "no such option", "usage:")


#: Writes the sandbox refused, which say nothing about the server. Matched on
#: the SHAPE of the failure -- a filesystem syscall against a path the run does
#: not make writable -- rather than on the word "ENOENT", because "no such
#: file" is also what a missing command looks like and conflating the two is
#: precisely the bug this replaced: four servers were reported as launched with
#: the wrong command when the harness had denied them their own state
#: directory. A harness that breaks a server and then blames it is not
#: measuring anything.
_DENIED_SYSCALLS = ("mkdir", "open", "mkdtemp", "writefile", "unlink", "rename",
                    "chmod", "symlink", "copyfile")


def _sandbox_denied(said):
    low = said.lower()
    if "read-only file system" in low or "erofs" in low:
        return True
    if not ("eacces" in low or "enoent" in low or "permission denied" in low):
        return False
    # A denial we caused names a syscall and a path we did not make writable.
    if not any("syscall: '" + c in low or "syscall: \"" + c in low
               for c in _DENIED_SYSCALLS):
        return False
    return not ("path: '/scratch" in low or "'/scratch" in low)


def _diagnose(attempts, image, limit=600):
    """Run the most likely command and keep what it said before dying."""
    if not attempts:
        return {"class": "no-command", "detail": "no launch command to try"}
    argv = attempts[0]
    try:
        out = subprocess.run(
            ["docker", "run", "--rm", "-i", "--network", "none",
             "--read-only", "--tmpfs", "/scratch:rw,noexec,nosuid,size=64m,mode=1777",
             "--tmpfs", "/home/saydo:rw,noexec,nosuid,size=32m,mode=1777",
             "-e", "HOME=/home/saydo", "-e", "TMPDIR=/scratch",
             "--cap-drop", "ALL",
             "--memory", "512m", "--workdir", "/scratch", image] + argv,
            input="", capture_output=True, text=True, timeout=45)
    except subprocess.TimeoutExpired:
        return {"class": "hangs",
                "detail": "started and never answered; probably waiting on "
                          "something it was not given"}
    except Exception as e:
        return {"class": "unknown", "detail": str(e)[:200]}

    said = ((out.stderr or "") + (out.stdout or "")).strip()
    low = said.lower()
    if _sandbox_denied(said):
        klass = "sandbox-denied"      # OUR containment, not their defect
    elif ("command not found" in low or "executable file not found" in low
          or "cannot find module" in low or "cannot find package" in low
          or "no such file or directory: " in low):
        klass = "wrong-command"       # our fault, and a different fix
    elif any(h in low for h in CREDENTIAL_HINTS):
        klass = "needs-configuration"
    elif "traceback" in low or "error:" in low or out.returncode not in (0,):
        klass = "crashes"
    else:
        klass = "silent"
    return {"class": klass, "exit": out.returncode,
            "detail": said[-limit:] if said else "said nothing at all"}


def main():
    if len(sys.argv) != 5:
        raise SystemExit(__doc__)
    cand_path, index, size, out_path = (sys.argv[1], int(sys.argv[2]),
                                        int(sys.argv[3]), sys.argv[4])
    with open(cand_path, encoding="utf-8") as fh:
        candidates = json.load(fh)["candidates"]
    batch = batch_of(candidates, index, size)
    if not batch:
        with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump({"batch": index, "results": []}, fh)
        print("batch {}: empty".format(index))
        return

    print("batch {}: {} packages".format(index, len(batch)))
    plans_mod.write_fixtures()
    tmp = tempfile.mkdtemp()
    images = write_dockerfiles(batch, tmp)

    built = {}
    for registry, (dockerfile, image) in images.items():
        ok, err = build(dockerfile, image)
        built[registry] = image if ok else None
        print("  image {}: {}".format(image, "built" if ok else "FAILED " + err))

    # What each image actually installed, so a console script is found rather
    # than guessed.
    bins = {reg: image_bins(img) for reg, img in built.items() if img}
    for reg, names in bins.items():
        print("  {} image provides {} executables".format(reg, len(names)))

    results = []
    for seq, c in enumerate(batch):
        image = built.get(c["registry"])
        if not image:
            results.append({"name": c["name"], "registry": c["registry"],
                            "outcome": "image-unavailable"})
            continue
        try:
            r = measure(c, image, bins.get(c["registry"], set()), seq)
        except Exception:
            r = {"name": c["name"], "registry": c["registry"],
                 "outcome": "error",
                 "error": traceback.format_exc(limit=3)[-400:]}
        results.append(r)
        # The reason is printed, not just the outcome: a sweep whose failures
        # are invisible in the log cannot be debugged from the log.
        why = (r.get("error") or "").replace("\n", " ")[-120:]
        print("  {:<40} {:<14} {}".format(c["name"][:40], r.get("outcome"), why))

    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump({"batch": index, "results": results}, fh, indent=2,
                  ensure_ascii=False)
        fh.write("\n")
    print("wrote {} ({} results)".format(out_path, len(results)))


if __name__ == "__main__":
    main()
