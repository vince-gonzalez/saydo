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

**Drift.** A tool redefined under an unchanged version number looks completely
ordinary in any single receipt; the deception exists only as a difference
between two runs. Receipts therefore chain to their predecessor, and a
redefinition with no version change is graded `serious` rather than noted.

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
    verifier/index.html    self-contained browser verifier, no network
    seeded/malserver.py    a server built to lie, so the harness can be tested

## Verify the verifier

`selfcheck` runs a seeded server that breaks six of its own promises on
purpose. If the harness reports it conformant, or attributes a finding to the
wrong invariant, then the harness is broken and no receipt it has ever produced
is worth anything. The declaration validator is checked the same way, against
five mutations it must reject.

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

- **Pipelock**, github.com/luckyPipewrench/pipelock — an agent firewall that
  mediates a running agent's traffic and emits signed receipts.

It is worth reading, and it solves a neighbouring problem rather than this one.
Pipelock's receipts record **actions** a deployed agent took; its contracts are
compiled by observing traffic; its canary is a synthetic environment variable,
which catches an agent exfiltrating its environment. A SayDo receipt is about
**an artifact** — one version of one tool, against a contract its author wrote
and signed before the run — and its canary is the tool's own input, which is
what separates *your data left* from *a request happened*.

One guards an agent you are already running. The other decides whether a tool
should be installed at all. They compose, and neither replaces the other.

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
