# The 5 evaders, run inside containment: CLEAN at the network layer

The 5 install-time fetchers that evaded a host-side proxy were installed inside
a container on an --internal network -- no route out except the SayDo proxy --
with decoy credentials planted and their per-run markers hunted in every request
body the proxy terminated. Run 33714507767, all steps green.

## Result

    @last9/mcp-server        CLEAN  github.com, registry.npmjs.org, release-assets
    wenlan-mcp               CLEAN  github.com, registry.npmjs.org, release-assets
    @mehmetsenol/gorev...    CLEAN  registry.npmjs.org
    vestige-mcp-server       CLEAN  github.com, registry.npmjs.org, release-assets
    @pandanpc/mcp-server     CLEAN  cos.pandanpc.com, registry.npmjs.org

    5/5 CLEAN   0 EXFIL   0 refused   every decoy marker stayed put

## What this establishes that the host could not

On the host these 5 were NOT-COVERED: they use https.get or a spawned binary,
neither of which honours a same-process proxy, so their egress was unobserved.
Two things changed in the container:

1. ENFORCEMENT. The first containment run (33701331074) caught @last9's own
   download-binary.js using https directly and BLOCKED it -- EAI_AGAIN
   github.com -- because the internal network has no route out except the
   proxy it did not use. The escape that succeeds on a host failed here.

2. OBSERVATION. Loading the postinstall's node with force_proxy routed its
   https through the proxy via a CONNECT tunnel, so the download completed AND
   every body was inspected. @last9 went from BLOCKED to completed-and-watched.
   The proxy saw all destinations, including @pandanpc's Tencent COS bucket,
   and found no decoy marker in any body.

## The honest verdict

These 7 MCP packages (the 5 here plus @astudioplus and jui-tools, clean on the
host) download executables from off-registry hosts at install -- content an
npm-tarball scan never sees -- and none of them exfiltrate credentials while
doing it. That conclusion is not reachable by static analysis, and it is not a
manufactured alarm: the same instrument fires on a planted exfiltrator
(exfilserver -> EXFIL with the marker in the body) and corrected a false
positive it first read into @ada-mcp. It discriminates, which is what makes a
CLEAN from it worth anything.

The remaining limit is unchanged and stated: this observes install behaviour.
What the downloaded binaries do when RUN is a separate question, for a separate
containment.
