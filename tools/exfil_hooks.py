"""Run install hooks behind an intercepting proxy: does a decoy credential leave?

The hook runner established that 7 MCP packages fetch code from off-registry
hosts at install. That is "downloads a binary". The sharper question is whether
any of them, while they are at it, reads one of the credential files sitting in
the home and puts it on the wire -- "downloads a binary AND exfiltrates".

Each hook runs in a decoy home whose credential files carry a unique marker,
behind the SayDo egress proxy terminating TLS with a throwaway CA. If that
marker appears in any outbound request body, the script did not merely fetch --
it exfiltrated a specific file, and the marker proves which one.

HARD LIMIT, stated up front: this runs the install SCRIPT, not the binary it
downloads. Executing a fetched executable on a real host is what a sandbox is
for, and there is none here. A clean result means the install script did not
exfiltrate; it says nothing about what the downloaded binary would do when run.
That second step belongs in the container.
"""

from __future__ import annotations

import io
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import hook_runner
import install_scripts
import package_probe as P
from egress_proxy import EgressProxy
from sandbox_ca import SandboxCA

MONITOR = hook_runner.MONITOR
DQ = chr(34)


def watch_hook(name, timeout=60):
    meta = install_scripts.manifest(name)
    if not meta:
        return {"name": name, "outcome": "no-manifest"}
    hook, body = hook_runner.hook_command(meta)
    parts = shlex.split(body or "", posix=False)
    if not (parts and parts[0] == "node"):
        return {"name": name, "outcome": "not-node-hook"}

    marker = "SAYDO-DECOY-" + os.urandom(4).hex()
    home = P._isolated_home(marker)
    pkgdir = tempfile.mkdtemp(prefix="saydo-xpkg-")
    log = tempfile.NamedTemporaryFile(delete=False, suffix=".jsonl")
    log.close()

    ca = SandboxCA()
    ca_file = os.path.join(home, "saydo-ca.pem")
    pem = ca.ca_pem()
    with io.open(ca_file, "wb") as fh:
        fh.write(pem if isinstance(pem, bytes) else pem.encode("utf-8"))

    proxy = EgressProxy(log.name, canaries=[marker], ca=ca).start()
    try:
        root, _ = hook_runner.fetch_scripts(name, meta,
                                            os.path.join(pkgdir, "package"))
        if not root:
            return {"name": name, "outcome": "no-tarball"}

        force = os.path.join(os.path.dirname(MONITOR), "force_proxy.js")
        pre = ["--require", MONITOR, "--require", force]
        if "-e" in parts:
            argv = ["node"] + pre + ["-e",
                    parts[parts.index("-e") + 1].strip(DQ)]
        else:
            script = parts[1].strip(DQ).replace(chr(92), "/")
            local = os.path.join(root, *script.split("/"))
            if not os.path.exists(local):
                return {"name": name, "outcome": "script-missing"}
            argv = ["node"] + pre + [os.path.abspath(local)]

        env = dict(os.environ)
        for v in ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
                  "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME"):
            env[v] = home
        env["HOMEDRIVE"], env["HOMEPATH"] = home[:2], home[2:]
        env["TEMP"] = env["TMP"] = env["TMPDIR"] = home
        env["INIT_CWD"] = home
        addr = proxy.address
        env2_proxy = addr
        env.update({"HTTP_PROXY": addr, "HTTPS_PROXY": addr,
                    "http_proxy": addr, "https_proxy": addr,
                    "NODE_EXTRA_CA_CERTS": ca_file,
                    "SSL_CERT_FILE": ca_file, "REQUESTS_CA_BUNDLE": ca_file,
                    "SAYDO_PROXY": addr})
        # Force the guarded probes to actually run, so a self-disabling script
        # is exercised on its live path rather than its skip path. This is the
        # adversarial reading: assume the risky branch runs.
        env["ADA_MCP_SLOW_START"] = "1"
        env["ADA_MCP_FORCE_PREINSTALL_PROBE"] = "1"
        try:
            subprocess.run(argv, env=env, cwd=home, timeout=timeout,
                           capture_output=True)
        except subprocess.TimeoutExpired:
            pass
    finally:
        proxy.stop()

    leaks, hosts = [], set()
    with io.open(log.name, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if row.get("host"):
                hosts.add(row["host"])
            if row.get("canary") == marker:
                leaks.append({"host": row.get("host"),
                              "method": row.get("method"),
                              "bytes": row.get("bytes")})
    shutil.rmtree(home, ignore_errors=True)
    shutil.rmtree(pkgdir, ignore_errors=True)
    try:
        os.unlink(log.name)
    except OSError:
        pass
    return {"name": name, "outcome": "ran", "hook": hook,
            "hostsSeenByProxy": sorted(hosts),
            "exfiltrated": bool(leaks), "leaks": leaks}


def main():
    targets = sys.argv[1:] or [
        "@last9/mcp-server", "wenlan-mcp", "@astudioplus/codegraph-mcp",
        "@mehmetsenol/gorev-mcp-server", "vestige-mcp-server",
        "jui-tools-mcp-server", "@pandanpc/mcp-server"]
    print("intercepting {} install hooks; decoy credentials planted, TLS "
          "terminated\n".format(len(targets)), flush=True)
    any_leak = False
    for name in targets:
        r = watch_hook(name)
        if r["outcome"] != "ran":
            print("  {:<36} ({})".format(name[:36], r["outcome"]), flush=True)
            continue
        if r["exfiltrated"]:
            any_leak = True
            for leak in r["leaks"]:
                print("  EXFIL  {:<34} decoy -> {} ({} bytes)"
                      .format(name[:34], leak["host"], leak["bytes"]),
                      flush=True)
        elif r["hostsSeenByProxy"]:
            seen = ", ".join(r["hostsSeenByProxy"][:3])
            print("  CLEAN  {:<34} proxy saw [{}], no decoy left"
                  .format(name[:34], seen), flush=True)
        else:
            # The proxy captured NOTHING. That is not clean -- it is blind. The
            # monitor saw this package resolve hosts, so egress happened and
            # went around the proxy. Reporting it clean would be exactly the
            # not-covered-as-pass error the project refuses.
            print("  NOT-COVERED {:<30} proxy captured no traffic; egress "
                  "evaded interception".format(name[:30]), flush=True)
    print("")
    print("EXFILTRATION DETECTED above" if any_leak else
          "No decoy marker left the traffic the proxy actually saw.")
    print("Limit: the install SCRIPT was run, not the binary it downloaded. "
          "That needs a container.")


if __name__ == "__main__":
    main()
