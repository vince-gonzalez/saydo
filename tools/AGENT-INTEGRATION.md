# saydo/status — the read an agent gates on

SayDo's distribution is not a human seeing a badge; it is an agent reading a
verdict at the moment it chooses a tool. `saydo/status` is that verdict:
compact, model-legible, derived from a signed receipt, and honest that it is a
summary and not the proof. This document is how it reaches the agent.

## The shape

`saydo/status` (schema: `spec/status.schema.json`) reduces a receipt to what a
caller needs to decide:

    verdict    warranted | failing | draft | unknown
    summary    one line, read the same way by a model and a person
    advice     a directive the agent acts on (refusal-first)
    envelope   the promises that held, in plain words
    checks     passed / failed / notCovered, with the failed ones named
    caveat     the observation limit, stated
    receipt    head + location + how to verify without trusting SayDo
    signature  who signed, and that the status did NOT check it (the receipt does)

An agent's gate is then trivial and does not trust SayDo:

    warranted -> USE, staying inside `envelope`
    draft     -> USE WITH CAUTION (tested, unsigned)
    failing   -> REFUSE (does more than it declares)
    unknown   -> REFUSE (never put under warrant)

`examples/agent_gate.py` runs exactly this over the receipts in this repo.

## How it reaches the agent (three delivery points, least to most work)

1. **Tool annotation.** MCP tools carry an `annotations` object. A server (or
   a gateway rewriting `tools/list`) attaches `annotations.saydo` with the
   status head and a URL. The agent reads it in the same `tools/list` it
   already fetches -- no extra round trip. This is the smallest change and the
   first thing to propose.

2. **Registry field.** The registry that serves a server's entry serves its
   current `saydo/status` beside it, so a client resolving a tool from the
   registry gets the verdict with the resolution. This is the "is this tool
   OK?" lookup, for machines.

3. **Gateway policy.** A gateway that already sits between agent and tool
   fetches the status and refuses to forward a call to a tool whose verdict is
   not `warranted` (or whose warrant is expired/revoked). Here the status stops
   being advice and becomes enforcement at the routing layer.

All three consume the same object. None requires trusting the transport: the
status names a receipt, and the receipt verifies in a browser with no account.

## Why this is the distribution, not a feature

A tool description is the one surface a model reliably reads. `saydo/status`
rides that surface. Because it is independently verifiable, a client can
consume it with zero trust in SayDo, which is what removes adoption friction.
Authors want the `warranted` verdict because agents prefer it; agents read it
because it bounds their risk. The registry that serves it becomes the endpoint
everyone hits. The single condition for any of this to matter is that the
verdict lands in the path the agent already traverses -- which is delivery
point 1, and the reason to bring `saydo/status` to the MCP working group as a
thing that already works rather than a proposal on a slide.

## What it does not do

It does not decide for the agent, and it does not vouch beyond what was
observed. `unknown` is the default, not `warranted`. A `warranted` verdict
bounds behavior to the declared envelope on the observed paths; it is not a
proof of containment (see `SANDBOX.md`). The status says so, in `caveat` and
`trust`, every time.
