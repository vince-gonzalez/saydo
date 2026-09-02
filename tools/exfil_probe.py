"""Watch a package read a credential AND ship it, with proof it was that file.

The credential-read channel says a package opened ~/.npmrc. The next question
-- did the contents leave? -- is the one no static analyser can answer, because
it is not a property of the source, it is a property of a run. This closes the
loop that the rest of the probe left half-built.

A package is imported inside a home furnished with decoy credentials, behind a
proxy that terminates TLS with a throwaway CA and reads request bodies. Each
decoy carries a unique marker. If that marker appears in an outbound body, the
package did not merely reference a credential path -- it read that specific
file and sent those specific bytes to a named host. The marker IS the evidence;
there is no inference about intent.

Everything reused: the egress proxy, the ephemeral CA, and the marker-matching
are the same machinery built for the abandoned MCP corpus. Only the driver is
new, and the driver is one import statement.
"""

from __future__ import annotations

import io
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import package_probe as P
from egress_proxy import EgressProxy
from sandbox_ca import SandboxCA


def watch_exfil(module, python=None, timeout=40):
    """Import `module` behind an intercepting proxy in a decoy home.

    Returns a dict naming which decoy markers left and to where.
    """
    python = python or sys.executable
    marker = "SAYDO-DECOY-" + os.urandom(4).hex()
    home = P._isolated_home(marker)
    log = tempfile.NamedTemporaryFile(delete=False, suffix=".jsonl")
    log.close()

    ca = SandboxCA()
    ca_file = os.path.join(home, "saydo-ca.pem")
    pem = ca.ca_pem()
    with io.open(ca_file, "wb") as fh:
        fh.write(pem if isinstance(pem, bytes) else pem.encode("utf-8"))

    # The marker the proxy hunts for is the exact string planted in the decoys.
    proxy = EgressProxy(log.name, canaries=[marker], ca=ca).start()
    try:
        env = dict(os.environ)
        for var in ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
                    "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME"):
            env[var] = home
        env["HOMEDRIVE"], env["HOMEPATH"] = home[:2], home[2:]
        addr = proxy.address
        env.update({"HTTP_PROXY": addr, "HTTPS_PROXY": addr,
                    "http_proxy": addr, "https_proxy": addr,
                    "SSL_CERT_FILE": ca_file, "REQUESTS_CA_BUNDLE": ca_file,
                    "CURL_CA_BUNDLE": ca_file, "NODE_EXTRA_CA_CERTS": ca_file})
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        try:
            subprocess.run([python, "-c", "import {}".format(module)],
                           env=env, timeout=timeout, capture_output=True)
        except subprocess.TimeoutExpired:
            pass
    finally:
        proxy.stop()

    leaks = []
    import json as _json
    with io.open(log.name, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                row = _json.loads(line)
            except ValueError:
                continue
            if row.get("canary") == marker:
                leaks.append({"host": row.get("host"),
                              "method": row.get("method"),
                              "bytes": row.get("bytes")})
    shutil.rmtree(home, ignore_errors=True)
    try:
        os.unlink(log.name)
    except OSError:
        pass
    return {"module": module, "marker": marker, "leaks": leaks,
            "exfiltrated": bool(leaks)}


def check():
    """A planted decoy that leaves must be caught, and a quiet import must not
    produce a phantom leak. [] = good."""
    problems = []

    caught = watch_exfil("exfilserver")
    if not caught["exfiltrated"]:
        problems.append(
            "a package that read a decoy credential and POSTed it was not "
            "caught leaving; the read-to-egress loop is open")
    else:
        leak = caught["leaks"][0]
        if not leak.get("host"):
            problems.append("an exfiltration was recorded without the host it "
                            "went to")

    quiet = watch_exfil("json")
    if quiet["exfiltrated"]:
        problems.append("a module that sends nothing was reported as "
                        "exfiltrating a credential")
    return problems


def main():
    argv = sys.argv[1:]
    if argv and argv[0] == "--check":
        found = check()
        for line in found:
            print("  " + line)
        print("exfil probe: {}".format(
            "all hold" if not found else "{} PROBLEM(S)".format(len(found))))
        raise SystemExit(1 if found else 0)
    if not argv:
        raise SystemExit(__doc__)
    for module in argv:
        r = watch_exfil(module)
        if r["exfiltrated"]:
            for leak in r["leaks"]:
                print("EXFIL  {:<20} decoy credential -> {} ({} bytes)"
                      .format(module, leak["host"], leak["bytes"]))
        else:
            print("clean  {:<20} no decoy marker left the process"
                  .format(module))


if __name__ == "__main__":
    main()
