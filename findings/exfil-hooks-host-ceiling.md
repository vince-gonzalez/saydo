# Pointing the exfil probe at the 7 fetchers: what a host can and cannot prove

The 7 packages that fetch code at install were run again, this time behind the
recording proxy with decoy credentials planted, to answer: does any of them
read a credential and ship it?

## Result (honest coverage, not rounded up)

    2/7  CLEAN       proxy saw the traffic, no decoy marker left
                     @astudioplus/codegraph-mcp (github.com),
                     jui-tools-mcp-server (raw.githubusercontent.com)
    5/7  NOT-COVERED proxy captured no traffic; egress evaded interception
                     @last9, wenlan, gorev, vestige, @pandanpc
    0/7  EXFIL

NOT-COVERED is reported as NOT-COVERED, never as clean. The first pass of this
tool called all 7 "clean" -- and 6 of them the proxy never saw. Reporting
blindness as cleanliness is the not-covered-as-pass error the project exists to
refuse, and it was caught before it shipped.

## Why 5 evade, precisely

A proxy in the SAME process is evadable, and Node evades it by default. A
dead-port test confirms it: `HTTPS_PROXY` pointed at a closed port, and both
global `fetch` and `https.get` still reached github with status 200. Node
honours neither variable without an explicit dispatcher/agent.

A --require preload (force_proxy.js) sets undici's global dispatcher and the
http/https agents, which captures `fetch`. It does NOT capture @last9, which
uses `https.get` directly and then `execSync("unzip ...")`. The monitor -- the
API-layer audit hook, always loaded -- SAW the evasion happen:

    CONNECT github.com:443
    CONNECT release-assets.githubusercontent.com:443
    SPAWN   unzip -o last9-mcp-server-<ts>.zip

So the monitor establishes WHO they contact and WHAT they spawn. The proxy,
which must be in the network path to read a body, cannot read bodies that route
around it. On a host you are not in the network path.

## The honest conclusion, and it is not a defeat

Two layers, two coverages:

- **API-layer monitor** (always loaded, unevadable by ordinary JS): reliably
  observes destinations and subprocess spawns. It proved all 7 fetch
  off-registry and that @last9 unzips a GitHub-release binary at install --
  content the npm tarball scan never sees.

- **Body inspection for exfil-proof** requires network-layer interception,
  which a host cannot guarantee and a container can: DNS sink + iptables
  redirect catch egress below the library, where https.get and a spawned curl
  both land. That layer already exists in this repo (tools/dns_sink.py, the
  iptables rules in tools/runner.py) and is where the 5 NOT-COVERED become
  covered.

The finding is therefore a mapped boundary: what is establishable on a host
(who + what-spawned, for all 7) versus what needs the container (body-level
exfil proof, for the 5 that evade a same-process proxy). The 2 that did route
through were clean.
