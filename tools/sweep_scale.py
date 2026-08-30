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


def commands_for(candidate):
    """Plausible in-container commands to start this server over stdio.

    A package rarely declares how it is launched in a way that can be read
    without installing it, so a small set of conventional names is tried. A
    server that answers none of them is recorded as unstartable, which is a
    finding about how hard the ecosystem is to audit, not a silent omission.
    """
    name = candidate["name"]
    bare = name.split("/")[-1]
    module = bare.replace("-", "_")
    if candidate["registry"] == "npm":
        return [[bare], ["npx", "-y", name]]
    return [[bare], [bare.replace("_", "-")],
            ["python", "-m", module]]


def measure(candidate, image, timeout=90):
    """Capture, infer, exercise, classify. Never raises."""
    name = candidate["name"]
    record = {"name": name, "registry": candidate["registry"],
              "version": candidate.get("version", ""),
              "description": candidate.get("description", "")}

    the_runner = runner_mod.make("container", image=image,
                                 tag="-" + abs(hash(name)).__str__()[:8])

    for argv in commands_for(candidate):
        plan = {"container_argv": list(argv), "exercise": [],
                "call_timeout": 30, "skip_fuzz": True}
        # Capture runs the server directly to read tools/list. It is still
        # inside a container, just without the proxy standing up first.
        probe = ["docker", "run", "--rm", "-i", "--network", "none",
                 "--read-only", "--tmpfs", "/scratch", "--cap-drop", "ALL",
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
        record["tally"] = report["tally"]
        record["dataFlow"] = report.get("dataFlow", {})
        record["findings"] = [
            {"invariant": v["id"], "type": v["type"],
             "evidence": v["evidence"][:300]}
            for v in report["verdicts"] if v["verdict"] == "fail"]
        return record

    record["outcome"] = "unstartable"
    record["error"] = "no conventional launch command produced a tools/list"
    return record


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

    results = []
    for c in batch:
        image = built.get(c["registry"])
        if not image:
            results.append({"name": c["name"], "registry": c["registry"],
                            "outcome": "image-unavailable"})
            continue
        try:
            r = measure(c, image)
        except Exception:
            r = {"name": c["name"], "registry": c["registry"],
                 "outcome": "error",
                 "error": traceback.format_exc(limit=2)[-300:]}
        results.append(r)
        print("  {:<42} {}".format(c["name"][:42], r.get("outcome")))

    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump({"batch": index, "results": results}, fh, indent=2,
                  ensure_ascii=False)
        fh.write("\n")
    print("wrote {} ({} results)".format(out_path, len(results)))


if __name__ == "__main__":
    main()
