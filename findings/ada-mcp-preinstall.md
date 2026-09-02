# Case study: @ada-mcp/mcp-server preinstall — why running beats reading

**Package:** `@ada-mcp/mcp-server@0.1.87` (npm, ~12k weekly downloads at time of writing)
**Method:** the package's own `preinstall` script, extracted from the published
tarball and run under the SayDo Node monitor in an isolated decoy home. No
source trust; every line below is an observed runtime event.

## What static analysis / manifest inspection reports

`scripts.preinstall = "node scripts/preinstall-probes.mjs"` — i.e. "runs code
at install." True, and where most tools stop.

## What reading the source suggests (and gets WRONG)

The script reads `~/.npmrc`, writes `~/.npmrc`, speed-tests remote registries
including China mirrors, and repoints Playwright downloads. Read cold, that is
an install-time network + credential-file-rewrite — a supply-chain smell.

## What RUNNING it establishes

Two runs, same package, in a decoy home:

1. **Default environment (what `npm install` actually produces):**
   The probe SELF-DISABLES. `isMcpFastStartEnv()` is hardwired
   `... || true`, so `isSkipPreinstallProbeEnv()` is always true and the
   script prints `skip probe` and exits. No network. No .npmrc write.
   **The install-time risk does not occur on a normal install.**

2. **Forced (`ADA_MCP_SLOW_START=1`), to see the gated behavior:**
   - Network to 6 hosts: registry.npmmirror.com, repo.huaweicloud.com,
     registry.npmjs.org, cdn.npmmirror.com, unpkg.com, cdn.playwright.dev
   - Wrote `~/.npmrc` (appended a `registry=` line)
   - Wrote `~/.ada-mcp-playwright-host`
   - Chose registry.npmjs.org (fastest at 1712 KB/s). Candidate hosts are
     BUNDLED, not fetched. It is a mirror optimizer, not a redirector.

## The finding

Not "this package is malicious" — it is not. The finding is the METHOD:
- Manifest inspection over-reports ("runs code at install").
- Source reading over-reports ("rewrites your npmrc / phones China mirrors").
- **Execution in isolation gives the true answer: the risky path is gated off
  in the published build and does not run on install.**

Static tools cannot distinguish a guarded, self-disabling script from a live
one, because the guard is a runtime environment check. Running it can. That
distinction is the entire reason this instrument exists.

## Reproduce

Fetch the tarball (no install), extract `scripts/*.mjs`, run
`node --require tools/monitor_boot/node_monitor.js scripts/preinstall-probes.mjs`
once with a clean env and once with `ADA_MCP_SLOW_START=1`, in a scratch HOME.
