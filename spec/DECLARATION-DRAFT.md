# Behavioral Declaration — specification draft 0.1.0

STATUS: DRAFT. Not published, not submitted, not final. Anything derived from
this document that goes anywhere public — working-group posts, spec text,
badges, landing copy — is rewritten by the supplier in the supplier's own
words first. This file is working material.

Product name provisional (SayDo / ASSAY); all identifiers carrying the name
are expected to change once.

## 1. What this is

A behavioral declaration is a machine-readable statement of how a tool is
permitted to behave, bound by digest to the exact tool definitions it covers,
testable by a harness, and signable by the supplier.

It extends the provenance layer; it does not replace it. TBOM v1.0.2 (Lovell,
2026, Zenodo 10.5281/zenodo.18459260) and CTMS 1.0 (Kanellopoulos, 2026)
establish that tool metadata is what the publisher released. Both state their
own ceiling: TBOM "cannot verify tool behavior matches descriptions"; CTMS
"verifies that a tool's claims haven't changed. It does not verify that those
claims are true." The declaration is the document that makes the second
question testable: it turns "behaves as described" from prose into a list of
invariants a harness can demonstrate or refute, run by run.

Interoperability is by construction, not translation:

- `Subject`, `Organization`, `Repository`, and `Signature` mirror the TBOM
  v1.0.2 definitions.
- Tool binding uses the TBOM `ToolDigest` computation unchanged: sha256 over
  the RFC 8785 canonical form of `{name, description, inputSchema}` (plus
  `outputSchema` / `annotations` where present). The same release yields the
  same digest values in its TBOM and in its declaration.
- A declaration attaches to an existing TBOM through the TBOM's own
  `attestations[]` array (`type: "custom"`, the declaration as evidence).
  No change to the TBOM schema is required or proposed.

## 2. Document model

Normative schema: `declaration.schema.json`. Field semantics not expressible
in JSON Schema:

**status.** `draft` or `declared`. A draft is a claim sheet: nothing in it
has been demonstrated. `declared` requires both of: (a) every invariant has
at least one passing conformance run against the bound artifact digests,
(b) a supplier signature over the RFC 8785 canonical form of the document
with the `signatures` array removed. A verifier treats anything else as a
draft regardless of what the field says.

**binding.** Every conformance run begins by recomputing the definition
digests from the live `tools/list` and comparing them to the binding. Any
mismatch stops the run: drifted definitions are a finding, and behavior of an
undeclared definition is not tested and not warranted. A live tool absent
from the binding is likewise a finding (undeclared surface), not a pass.

**invariants.** The unit of meaning. Receipts cite invariants by `id`. An
invariant an environment cannot check is reported as NOT COVERED, never as
passed. The declaration is falsifiable by design; a declaration nothing could
refute warrants nothing.

## 3. Invariant types, 0.1.0

Scope note: `appliesTo: ["*"]` covers the whole server process including
startup and shutdown, not just the union of tool invocations.

| type | claim | demonstrated by |
|---|---|---|
| `no-network` | no network egress during the covered activity | egress monitoring during exercise |
| `network-allowlist` | egress only to `params.hosts` | egress monitoring; any other host refutes |
| `no-write` | no filesystem writes | filesystem monitoring |
| `write-scope` | writes only under `params.paths` (env-var templates) | filesystem monitoring |
| `read-scope` | reads only: own artifact and runtime files, plus paths named by the arguments listed in `params.pathArgs`, plus `params.alsoAllowed` | filesystem monitoring |
| `no-subprocess` | no child processes | process monitoring |
| `subprocess-scope` | starts only the programs named in `params.programs`, matched on basename | process monitoring; any other program refutes |
| `deterministic` | identical arguments and identical bytes of files named by `params.pathArgs` produce identical results, after removing every field named in `params.volatile` (recursively) | two same-instance calls and one fresh-instance call, compared |
| `error-as-value` | malformed or out-of-domain input produces an error in the result payload; the transport never sees an exception or crash | fuzzing and adversarial input |
| `refusal-tool` | the server exposes `params.tool`: listed in `tools/list`, takes no arguments, performs no I/O, and states what the server cannot answer | invocation under monitoring |
| `no-data-egress` | egress may occur, but none of it carries the tool's own input | a marker planted in the input and looked for in outbound bodies, across two runs with different markers |
| `property` | the named semantic check `params.check` holds; `params.statement` is the human-readable claim | an executable check the harness carries |

`no-data-egress` is the one that answers the question people actually have.
Observing a request tells you a request happened; it does not tell you whether
your data left. Establishing this requires intervening on the input rather than
watching traffic: run twice with a different marker each time, and classify
each destination by whether what it received changed with the input.
`input-dependent` means the payload carried what you gave it;
`input-independent` means it did not. An opaque body is reported `unexamined`,
never `clean` — a payload that could not be read is not evidence that nothing
left.

### A negative claim requires demonstrated conduct

Normative, and an implementation that skips it produces receipts that look like
these and mean something else. The types phrased as *it does not do X* —
`no-network`, `no-write`, `no-subprocess`, `write-scope`, `read-scope` — may
only be reported `pass` if the run observed the tool doing something. A run in
which no call window produced any observable effect returns `not-covered` for
all of them.

Without this rule a server that starts, lists its tools and declines every call
satisfies every negative invariant simultaneously and earns a signed
conformance receipt, having done nothing. It made no network request the way an
unplugged machine makes none. This is not a corner case: in a sweep of MCP
servers published to public registries, declining every call was the commonest
behaviour by a wide margin, so the rule decides what a receipt means for most
of the population.

A `refusal-tool` pass does not count as conduct. The server answering a
question about itself is not the server behaving, and a warrant resting on it
is one the subject issued to itself.

The cost is stated rather than hidden: a tool that genuinely performs no I/O
also produces no observable effect, and cannot establish `no-network` this way
either. That is the correct reading of the evidence — computing quietly and
declining to compute are indistinguishable from outside — and such a tool earns
coverage through `deterministic`, `error-as-value` or `property`, which are
judged on what it returned rather than on what it touched.

What the table buys: tool poisoning, capability rug-pulls, and silent
behavioral drift are all the same event under this model — a conformance run
whose observations exceed the declaration.

## 4. What a declaration does not claim

It does not claim the tool is useful, correct in its domain, or safe for a
purpose. It claims the tool's observable behavior stays inside the declared
envelope, and the envelope is published. A tool may honestly declare a wide
envelope (`authorecon` declares no egress bound at all for its
link-resolution tools, because following the record wherever it points is the
tool's function). The value is that the envelope is stated, signed, and
continuously checked — not that every envelope is narrow.

## 5. Open questions (for the working-group conversation, in his words)

- Whether `covers` should grow an `annotations` requirement once MCP tool
  annotations stabilize.
- Whether an egress observation belongs in the receipt even when no egress
  invariant is declared (observed-but-unclaimed telemetry).
- Signature transport: detached JWS vs DSSE envelope; TBOM allows three.
- Whether `deterministic` needs a seeded-randomness carve-out
  (`params.seedArg`) before any real generator tool declares it.
