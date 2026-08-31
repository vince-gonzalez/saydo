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

<!-- mcp-name: io.github.vince-gonzalez/saydo -->

**Does the tool do what it says?** Not is it safe, not is it good. A publisher
declares what an MCP tool does in a signed contract; SayDo runs the tool in a
sandbox, checks it against that contract, and emits a hash-chained receipt
anyone can verify in a browser with no account and no trust in the issuer.

## The MCP server

    pip install "saydo[mcp]"
    saydo-mcp

Four tools, and the first one is a refusal:

| tool | answers |
|---|---|
| `scope` | what SayDo cannot settle. Call it first. |
| `status` | whether a package has a receipt, and what that receipt establishes |
| `inspect_definition` | the RFC 8785 tool digest, and wording aimed at the model rather than at a reader |
| `check_now` | run a package in a sandbox and report what it did |

Most packages have no receipt, so the usual answer is `unknown`. That keeps
meaning *nobody has looked*. It never softens into *probably fine*.

## What a verdict can be

    pass          the declared behaviour held under the run
    fail          the tool did something it declared it would not
    not-covered   the run established nothing either way

A whole run resolves to CONFORMANT, NOT CONFORMANT, or INCONCLUSIVE.

`INCONCLUSIVE` carries most of the weight. A server that declines every call
makes no network request the way an unplugged machine makes none, and a harness
that scores that as three passes has certified nothing at all. A negative claim
passes here only if the run observed the tool actually doing something.

## What this is not

It is not a safety guarantee and no receipt should be presented as one. It says
what one version of one tool did on one run, against a contract its author
wrote beforehand. Drift detection and hash-chained receipts are not novel; the
repository names the prior art rather than claiming otherwise.

`check_now` needs Docker and the repository, and refuses plainly when it does
not have them rather than running something weaker and reporting it as a
sandboxed result.

Source, specification, the browser verifier, and the seeded fixtures that exist
to prove the harness can fail:
https://github.com/vince-gonzalez/saydo

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
and internet products.
