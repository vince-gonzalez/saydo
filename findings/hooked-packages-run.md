# Running 67 npm MCP install hooks in isolation: what static analysis misses

Every npm package in the MCP corpus that declares an install hook (67 of 1,641)
had its actual install script executed under the SayDo monitor, in a decoy home
with no real credentials present. Not the manifest, not the source -- the code.

## Result

    44  node-driven hooks ran
    23  non-node hooks (pnpm guards, toolchain builds) -- recorded, not run
    --
    31  self-disabled on a default install (guarded by a runtime env check)
     7  contacted a network host
     3  downloaded and wrote a file
     0  read a decoy credential

Zero credential reads is the true negative that makes the rest credible: the
instrument is not flagging everything.

## The finding: 7 packages fetch code from off-registry hosts at install

| package | contacts | writes at install |
|---|---|---|
| @last9/mcp-server | github.com, release-assets.githubusercontent.com | last9-mcp-server-*.zip |
| wenlan-mcp | github.com, release-assets.githubusercontent.com | wenlan-windows-x64.zip |
| @astudioplus/codegraph-mcp | github.com, release-assets | (fetch) |
| @mehmetsenol/gorev-mcp-server | github.com, release-assets | (fetch) |
| vestige-mcp-server | github.com, release-assets | (fetch) |
| jui-tools-mcp-server | raw.githubusercontent.com | (fetch) |
| @pandanpc/mcp-server | cos.pandanpc.com (Tencent COS) | (fetch) |

These are "download the prebuilt binary" postinstalls. They are not shown to be
malicious. The point is the trust boundary they cross:

**The published npm tarball is auditable. The executable these seven actually
run is NOT in the tarball -- it is fetched at install time from a GitHub release
or, in one case, a personal Tencent Cloud bucket (cos.pandanpc.com).** A static
scan of the npm package (Socket.dev and every SCA tool) sees a postinstall and
cannot see what it downloads, because the payload is not in what was scanned.
Running the install is the only way to observe wenlan-mcp pull a Windows binary
from the network. This instrument observed it; static analysis structurally
cannot.

The one non-GitHub host, cos.pandanpc.com, is the weakest trust anchor in the
set: a personal object-storage bucket is a softer supply-chain target than a
GitHub release, and worth a closer look.

## Contrast with the guarded majority

31 of 44 self-disabled: their install script runs, checks a runtime condition
(package manager, an env flag, presence of .git) and exits. Static analysis
cannot distinguish these from live scripts, because the guard is a runtime
check -- it reports all 44 as "runs code at install." Execution separates the
31 that do nothing from the 7 that reach the network.

## Reproduce

    python tools/hook_runner.py corpus/hooked-names.json out.json

Fetches each tarball (no install), runs its node hook under
tools/monitor_boot/node_monitor.js in a scratch HOME, records observed events.
