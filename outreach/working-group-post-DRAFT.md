# DRAFT — behavioral-conformance extension, for the TBOM/CTMS thread

STATUS: DRAFT — placeholder wording, to be rewritten in the author's voice and
signed before it goes anywhere. Nothing here is posted. Fill or cut the two
bracketed items: the repo link (only if the repo is made public) and the
name/handle.

Target: modelcontextprotocol discussion #2189 (TBOM), and/or George
Kanellopoulos's CTMS repo. Register: plain, technical, first person, builder —
not marketing.

---

I've been building on top of TBOM and CTMS and want to bring something back
to the thread.

Both establish that a tool's metadata is what the publisher released, and both
state their own ceiling plainly: TBOM "cannot verify tool behavior matches
descriptions," and CTMS verifies that a tool's claims haven't changed, not
that they're true. I've been working the layer past that — proving a tool
behaves as its declaration says, with a receipt anyone verifies without
trusting me — and I think it belongs as an extension of your work, not a fork.

The shape:

1. A behavioral declaration: a machine-readable contract of what a tool is
   permitted to do — no network, writes only within a named path,
   deterministic, returns errors as values, and so on. It binds to the same
   tool-definition digests TBOM records (sha256 over the RFC 8785 canonical
   form of name/description/inputSchema) and attaches as a TBOM attestation.
   No change to the TBOM schema.

2. A conformance harness that exercises the tool — property tests, adversarial
   input, egress observed at a network boundary so it works across languages,
   filesystem and subprocess observed in-runtime — and reports pass, fail, or
   not-covered per invariant. It is refusal-first: it cannot prove an invariant
   it did not exercise, and it reports that as not-covered rather than passing
   it. It also ships with a server built to fail, and has to catch it, so a
   green result means something.

3. A hash-chained, signed receipt: canonical JSON, row_hash =
   sha256(prev_hash + row), a genesis anchor, an Ed25519 signature over the
   head. An auditor re-verifies the chain and the signature in a browser, with
   no account and no trust in me.

4. A compact status an agent reads at tool-selection time to gate a tool —
   warranted, failing, draft, or unknown — refusal-first, with a pointer back
   to the receipt for the proof.

So this isn't a slide: there's a running reference implementation, exercised
against five live MCP servers, plus a third-party server where it caught a real
gap. mcp-server-fetch's tool description says only that it fetches a URL and
extracts markdown; it also spawns a subprocess (node, for Readability.js). The
harness surfaced that automatically and I confirmed it in the source. That
description-to-behavior gap is the thing this is for.

The honest limit, stated up front: this observes behavior, it does not contain
it. A tool built to evade observation — a raw socket to a bare IP, in a
language the in-runtime hook can't reach — can act unseen on a host without
network isolation. Enforcement (a network-isolated container) is a deployment
concern; the part I'm proposing to standardize is the declaration, the receipt,
and the status.

Three questions for the group:

- Does a behavioral-conformance extension belong under TBOM attestations, or as
  a sibling document that references a TBOM by serial number?
- Should the agent-facing status ride in the tool's `annotations`, so a client
  reads it in the `tools/list` it already fetches, with no extra round trip?
- Is there appetite to co-author this as an addition to the current work,
  rather than a separate spec?

Prior art I'm citing so it's on the record, none of it continuous behavioral
conformance to a declared contract with independently-verifiable receipts:
RAILS (arXiv:2606.08790), Anumati (arXiv:2604.16524), and Attested Tool-Server
Admission (arXiv:2605.24248).

Happy to share the declaration schema, the harness, and the browser verifier.
[ — your name/handle ] [ repo: link, if you decide to make it public ]

---

## Notes for you (not part of the post)

- Keep or cut the mcp-server-fetch example. It is true and it is the strongest
  single line, but it names another author's tool in a critical light. It reads
  as a capability finding, not an accusation (subprocess use is a known
  readabilipy design), and that's how I framed it — your call whether to lead
  with it, soften it, or drop it.
- Do not link the repo unless you've decided it's public. The post stands
  without a link; you can offer the schema on request instead.
- If you'd rather open with CTMS (Kanellopoulos, Apache-2.0) than the TBOM
  discussion, the same text works with the first line pointed at his repo.
