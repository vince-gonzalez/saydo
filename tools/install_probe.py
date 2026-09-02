"""What a package's install scripts actually DO, not just that it has them.

install_scripts.py counts packages that CAN run code on `npm install`. This
answers the next question: what does that code do. And it answers it the same
way everything else here does -- by running it in a decoy home behind a
recording proxy, and reading what left.

The counterfactual is the method. Install once with --ignore-scripts and once
without, into fresh prefixes, and diff. What only the second run touched is
what the install script did, isolated from what npm itself does. A network
call, a credential read, a decoy marker on the wire -- attributed to the
package's own install code, not to the installer.

    npm install --ignore-scripts   baseline: what the installer does
    npm install                    treatment: installer + the package's scripts
    difference                     the package's scripts, alone

This runs `npm install`, which fetches and executes third-party code, so it is
CONTAINED, not run on a host. It requires Docker and belongs in CI. The logic
below is self-tested without Docker so it arrives working rather than debugged
in a runner -- the corpus sweep was debugged in the runner and cost a week.
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


def diff_events(baseline, treatment):
    """Events in the treatment run that the baseline run did not produce.

    The baseline is `--ignore-scripts`: npm doing its own work, no package
    hooks. Anything here that is not in the baseline is the package's install
    code acting. Signatures, not identity, so a repeated ordinary event in the
    baseline masks the same event in the treatment -- the conservative
    direction, which under-reports rather than invents.
    """
    seen = {P._signature(e) for e in baseline}
    caused = [e for e in treatment if P._signature(e) not in seen]
    net = [e for e in caused if e.get("event", "").startswith("socket")]
    proc = [e for e in caused if e.get("event") == "subprocess.Popen"]
    secrets = P.secret_reads(caused)
    return {"network": [e.get("args") for e in net][:20],
            "subprocess": [e.get("args") for e in proc][:20],
            "secretReads": secrets[:20],
            "acted": bool(net or proc or secrets)}


def classify(diff, exfil_markers):
    """Turn a diff into a verdict. Refusal-first, like the harness.

    A package whose install code did nothing observable is `quiet`, never
    `clean`: containment plus a no-op installer is a real thing, but so is an
    install script that waits for a signal we did not give, and the two look
    identical from here.
    """
    leaked = diff.get("exfiltrated")
    if leaked:
        return "exfiltrated-credential"
    if diff.get("secretReads"):
        return "read-credential"
    if diff.get("network"):
        return "contacted-host"
    if diff.get("subprocess"):
        return "spawned-process"
    return "quiet"


def check():
    """The diff and classification logic, tested without Docker. [] = good."""
    problems = []

    base = [{"event": "open", "intent": "read", "path": "/x/package.json"},
            {"event": "socket.getaddrinfo", "args": ["registry.npmjs.org"]}]
    # Treatment repeats the baseline, then adds the install script's own acts:
    # a credential read and a call to a host the baseline never touched.
    treat = base + [
        {"event": "open", "intent": "read",
         "path": "/home/saydo-home-x/.npmrc"},
        {"event": "socket.getaddrinfo", "args": ["evil.example.com"]}]
    d = diff_events(base, treat)

    if not d["acted"]:
        problems.append("an install script that read a credential and called a "
                        "new host was diffed to nothing")
    if not d["secretReads"]:
        problems.append("the credential read was not isolated from the "
                        "baseline")
    base_call_in_diff = any("registry.npmjs.org" in json.dumps(a)
                            for a in d["network"])
    if base_call_in_diff:
        problems.append("the installer's OWN registry call leaked into the "
                        "diff; the baseline is not being subtracted")
    # And prove subtraction happens at all: a treatment that only repeats the
    # baseline must diff to EMPTY. If _signature stops distinguishing events,
    # nothing subtracts and this is where it shows.
    same_content = [json.loads(json.dumps(e)) for e in base]
    identical = diff_events(base, same_content)
    if identical["network"] or identical["secretReads"]:
        problems.append("a treatment with the SAME content as the baseline "
                        "produced a non-empty diff; the signature keys on "
                        "identity, not content, so nothing subtracts")
    if not any("evil.example.com" in json.dumps(a) for a in d["network"]):
        problems.append("the host only the install script contacted was lost")

    # A package whose install run is identical to the baseline did nothing.
    quiet = diff_events(base, list(base))
    if quiet["acted"]:
        problems.append("a package whose install matched the baseline was "
                        "reported as having acted")
    if classify(quiet, []) != "quiet":
        problems.append("an inert install was not classified quiet")

    if classify({"secretReads": [{"path": "/h/.npmrc"}], "exfiltrated": True},
                []) != "exfiltrated-credential":
        problems.append("exfiltration is not the top verdict")
    if classify({"secretReads": [{"path": "/h/.npmrc"}]}, []) \
            != "read-credential":
        problems.append("a credential read was not classified")

    return problems


def main():
    argv = sys.argv[1:]
    if argv and argv[0] == "--check":
        found = check()
        for line in found:
            print("  " + line)
        print("install probe logic: {}".format(
            "all hold" if not found else "{} PROBLEM(S)".format(len(found))))
        raise SystemExit(1 if found else 0)
    print(__doc__)
    print("Execution path requires Docker and runs in CI. "
          "Logic is verified with --check.")


if __name__ == "__main__":
    main()
