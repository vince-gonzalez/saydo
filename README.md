```
╔════════════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                            ║
║                         ███████╗ █████╗ ██╗   ██╗██████╗  ██████╗                          ║
║                         ██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗██╔═══██╗                         ║
║                         ███████╗███████║ ╚████╔╝ ██║  ██║██║   ██║                         ║
║                         ╚════██║██╔══██║  ╚██╔╝  ██║  ██║██║   ██║                         ║
║                         ███████║██║  ██║   ██║   ██████╔╝╚██████╔╝                         ║
║                         ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═════╝  ╚═════╝                          ║
║                                                                                            ║
║                               does the tool do what it says                                ║
║                                                                                            ║
╚════════════════════════════════════════════════════════════════════════════════════════════╝
```

**DRAFT COPY — pending the owner's pass.** Everything below is measured or
mechanical, and none of it is a marketing claim, but the wording has not been
approved.

A publisher declares, in a signed machine-readable contract, exactly what a
tool does. A harness makes the tool run and checks it against that contract.
Every run emits a hash-chained receipt anyone verifies in a browser, with no
account, and without trusting the issuer.

The question it answers is narrow on purpose: **does this tool do what it
says?** Not is it safe, not is it good. A tool that refuses to act has not been
shown to be safe — it has not been shown anything, and SayDo says that in those
words rather than returning a green tick.

## What a verdict can be

    pass          the declared behaviour held under the run
    fail          the tool did something it declared it would not
    not-covered   the run established nothing either way

`not-covered` is never quietly upgraded to `pass`. Most of the interesting
failures in this domain come from silence being read as good behaviour.

And a whole run resolves to one of four things, not two:

    CONFORMANT      it did what it said, and it was shown doing it
    NOT CONFORMANT  it did something it declared it would not
    INCONCLUSIVE    nothing failed, and nothing was established
    (revoked / expired, once a registry has spoken)

`INCONCLUSIVE` carries most of the weight. A server that declines every call —
the commonest kind in the public sweep — makes no network request, writes no
file and starts no process, so a naive harness marks all three as passes and
issues a warrant for a program that did nothing. SayDo requires a run to have
demonstrated *conduct* before any of those checks can pass, and a server
describing itself does not count as conduct.

## In your CI

    - uses: vince-gonzalez/saydo@main
      with:
        command: python -m my_server
        declaration: saydo.declaration.json

The build fails if the tool breaks its declaration, and also if the run
established nothing — because a green check that proves nothing is worse than
no check, being a claim of conformance that nobody actually made. Set
`require-coverage: false` to let such a build through; the receipt still
records it as `inconclusive` and never as a warrant.

This is the place the tool is worth the most. Coverage comes from the tool
actually doing its work, which needs the credentials and inputs it accepts —
and those exist in the publisher's own CI and essentially nowhere else.

## Run it on anything

`saydo` puts one tool under test and writes a receipt. The tool does not have
to be yours, and it does not have to be an F-Keys one:

    python cli/saydo.py verify --npm  @modelcontextprotocol/server-memory --sandbox
    python cli/saydo.py verify --pypi mcp-server-time --sandbox
    python cli/saydo.py verify --command "python my_server.py" --declaration mine.json

With `--declaration`, the author's own contract is the thing being tested.
Without one, a deliberately conservative contract is inferred and most
invariants come back `not-covered` — the honest result for a stranger poking at
a server they have no credentials for.

`--sandbox` runs the server inside a container whose only route out is a
recording proxy (Linux and Docker; the containment is proven in CI, and
`tools/SANDBOX.md` states plainly what it does and does not cover). Without it
the run is *observed*, not enforced, and the receipt says `observed`, so no
claim can outrun the mechanism that produced it.

Then check the result yourself:

    python cli/saydo.py status certivl        # the one-shot verdict an agent reads
    python cli/saydo.py selfcheck             # prove the harness can fail

Open `verifier/index.html`, paste in the receipt and the anchor, and the page
recomputes the entire chain and the signature in your browser. No request
leaves it.

## The four layers

    1  declaration   what the publisher promises, signed  (spec/)
    2  harness       makes the tool act, and watches      (tools/harness.py)
    3  receipt       hash-chained, signed, verifiable     (tools/receipt.py)
    4  registry      what is still true, and until when   (tools/registry.py)

Layer 4 exists because a receipt is a fact about one moment, and left there it
answers the wrong question. Nobody choosing a tool wants to know it behaved in
August. Claims therefore expire at read time, so nothing stays green merely
because no one re-ran it, and a revocation is sticky: publishing a newer
passing receipt over a withdrawn claim records the attempt and does not lift
the withdrawal.

## Two things here that are not standard practice

**The counterfactual.** Watching a tool make a network call tells you it made a
call. It does not tell you whether your data left. So the tool is run twice
with different inputs, and each destination is classified by whether what it
received changed with the input: `input-dependent` means the payload carried
what you gave it, `input-independent` means it did not, and an opaque body is
reported `unexamined` rather than clean. *It sent your input to example.com* is
a different sentence from *it made a request*, and only the first one is worth
anything to the person deciding.

Demonstrated by `seeded/leakserver.py`, which exists because this was claimed
here before it was tested. Two tools contact the same host on every call.
`submit` posts the text it was given; `ping` posts a fixed body:

    FAIL  network.none     egress: ping->example.com; submit->example.com
    FAIL  data.stays-put   the tool sent its own input data out:
                           submit -> example.com. Established by changing the
                           input between runs: example.com is input-dependent

`network.none` sees both and cannot separate them, which is what watching
traffic gets you. `data.stays-put` names only `submit`.

**The correction that made this real.** Until 2026-08-31 the marker was planted
only in `SAYDO_CANARY`, an environment variable, and the only fixture that ever
carried it out read it from there — which is the mechanism the prior art
already uses, not a different one. Nothing put the marker into a tool's
arguments, so across 279 third-party servers the proxy searched for a string
that had never been in any input, and all 279 came back `unexamined`. The
marker now goes into the arguments each run is given, one per run, which is
what the paragraph above always said it did.

**Drift.** A tool redefined under an unchanged version number looks completely
ordinary in any single receipt; the deception exists only as a difference
between two runs. Receipts therefore chain to their predecessor, and a
redefinition with no version change is graded `serious` rather than noted.

This one is **not** unusual, and it was listed here as though it were until a
proper look at the field turned up several projects doing it — see *Adjacent
work* below. `askalf/truecopy` pins a vetted tool definition by content hash
and fails a CI run when the bytes change, which is drift detection by another
name and shipped before this. The distinctive claim is narrower than it first
appeared: the counterfactual above, and testing behaviour against a contract
the author wrote, rather than checking that the bytes are the ones you vetted.

## Layout

    spec/                  the declaration schema and its field semantics
    tools/harness.py       the conformance harness      (tools/HARNESS.md)
    tools/runner.py        local vs contained execution (tools/SANDBOX.md)
    tools/egress_proxy.py  recording proxy, allowlist enforcement, TLS inspection
    tools/canary.py        marker generation and body examination
    tools/differential.py  the two-run counterfactual classifier
    tools/drift.py         what changed since the previous receipt
    tools/registry.py      expiry and sticky revocation
    tools/status.py        receipt -> the compact object an agent reads
    tools/declare.py       draft a declaration from an observed run
    tools/discover.py      find MCP servers on npm and PyPI
    tools/sweep_scale.py   measure many of them, in batches
    action.yml             SayDo as a GitHub Action
    verifier/index.html    self-contained browser verifier, no network
    seeded/malserver.py    a server built to lie, so the harness can be tested
    seeded/silentserver.py a server that declines everything, so the harness
                           can be tested against reporting silence as clean

## Verify the verifier

`selfcheck` runs a seeded server that breaks six of its own promises on
purpose. If the harness reports it conformant, or attributes a finding to the
wrong invariant, then the harness is broken and no receipt it has ever produced
is worth anything. The declaration validator is checked the same way, against
five mutations it must reject.

A second fixture does the opposite and matters just as much: it starts, lists
its tools, and declines every call. The harness must report that as
`INCONCLUSIVE`. When it reported `CONFORMANT` — which it did, and the receipt
was signed — the mark meant nothing, since that is what most public MCP servers
do when a stranger calls them.

CI asserts both, on the library and on the Action: a build must fail on a tool
that lies, and on a run that shows nothing.

A check that cannot fail for the reason you care about is not a check.

## Prior art this builds on

- **TBOM v1.0.2**, Jason M. Lovell, 2026 — 10.5281/zenodo.18459260
- **CTMS 1.0**, George Kanellopoulos, 2026 — github.com/gkanellopoulos/ctms

Both are provenance: they establish that tool metadata is what the publisher
released, and both state that verifying behaviour against that metadata is out
of their scope. That out-of-scope line is what this repository is for. A SayDo
declaration attaches through TBOM's existing `attestations[]` and reuses its
`ToolDigest` format, so nothing here forks either of them.

## Adjacent work, and where the line is

This section keeps growing, which is the useful thing about it. Each of these
was found after something here had already been described as unusual, so the
list is also a record of claims that had to be narrowed.

- **Pipelock**, github.com/luckyPipewrench/pipelock — an agent firewall that
  mediates a running agent's traffic and emits signed receipts.
- **truecopy**, github.com/askalf/truecopy — vets a tool definition, pins it by
  content hash with an optional Ed25519 signature, and fails CI when the bytes
  change. Paired with **redstamp** for runtime containment.
- **Proofpane**, github.com/Proofpane/releases — a governance proxy recording
  every tool call to a hash-chained audit log, exported as an Ed25519-signed,
  offline-verifiable evidence pack. Closed source; that repository is a
  download mirror.
- **dcl-webhook**, github.com/Fronesis-Labs/dcl-webhook — policy verdicts
  written to a tamper-evident SHA-256 hash chain.

The line is not the cryptography. A hash-chained, signed, offline-verifiable
record is now a common design, and this repository does not claim otherwise.

The line is **what the record is about**. Pipelock and Proofpane attest to
**actions** a deployed agent took. truecopy attests that a tool is **the same
bytes** you vetted — integrity, which catches a silent update and is silent
about a tool that was always misbehaving. A SayDo receipt attests that **one
version of one tool did what its author said it would**, tested by running it,
against a contract written before the run.

Integrity asks *is this the thing I approved?* Conformance asks *does the thing
do what it claims?* Both are worth having, and neither answers the other.

What still appears to be unshared, on the evidence gathered so far: the
two-run counterfactual that separates *your data left* from *a request
happened*, and refusing to call a tool clean when it merely declined to act.
If either turns out to have prior art, it belongs in this list and the claim
above should be cut rather than defended.

That first claim was overstated here for a week. The difference from Pipelock
was given as *their canary is an environment variable, ours is the tool's own
input* — and ours was also an environment variable. It is the tool's input as
of 2026-08-31, with a fixture that demonstrates the argument case, and the
sentence is kept honest by that fixture rather than by this paragraph.

## Status

Public working repository. Receipts produced here are signed with a
proof-of-concept key held by F-Keys Creative LLC; production signing is not
settled. The corpus measurements are a draft pending the owner's pass, and
every figure in them is a lower bound — servers were run without credentials,
so a credentialed server may do more than was recorded.

Licence: the open layers — the declaration schema and spec text (`spec/`), the
reference tooling (`tools/`), the browser verifier (`verifier/`), and the
seeded fixture (`seeded/`) — are Apache-2.0 (see LICENSE, NOTICE). Signed
public artifacts are not placed under any licence by this repository.

---

```
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║      ███████╗      ██╗  ██╗███████╗██╗   ██╗███████╗       ║
║      ██╔════╝      ██║ ██╔╝██╔════╝╚██╗ ██╔╝██╔════╝       ║
║      █████╗  █████╗█████╔╝ █████╗   ╚████╔╝ ███████╗       ║
║      ██╔══╝  ╚════╝██╔═██╗ ██╔══╝    ╚██╔╝  ╚════██║       ║
║      ██║           ██║  ██╗███████╗   ██║   ███████║       ║
║      ╚═╝           ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝       ║
║                                                            ║
║               ·   C  R  E  A  T  I  V  E   ·               ║
║                                                            ║
║          ────────────────────────────────────────          ║
║                                                            ║
║                      Vincent Gonzalez                      ║
║                         f-keys.com                         ║
║                 ORCID 0009-0005-3640-014X                  ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
```

Part of [F-Keys](https://f-keys.com) — independent hardware, software
and internet products. See the [working log](https://f-keys.com/log/)
and [live status](https://f-keys.com/status/).
