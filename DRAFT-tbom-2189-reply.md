# DRAFT — reply to modelcontextprotocol #2189

Not posted. Yours to edit or bin.

Thread: https://github.com/modelcontextprotocol/modelcontextprotocol/discussions/2189
In it: @jlov7 (TBOM), @gkanellopoulos (CTMS), @SamMorrowDrums (maintainer)
Dormant since 2026-04-19.

---

Jason — you listed "doesn't verify tool behaviour matches descriptions" as a
known gap. I built that on top of your format, mostly to find out how badly it
could go.

Quite badly, as it turns out. The first thing my harness did was hand a signed,
conformant receipt to a server that had done nothing at all. It started, listed
its tools, declined every call, and thereby satisfied "no network, no writes,
no subprocesses" perfectly. Silence reads as compliance unless you go out of
your way to refuse it.

Not an edge case, either: of the 3,470 servers in punkpeye/awesome-mcp-servers,
2,889 carry no install command in their entry. A stranger can't start most of
these, never mind watch them work. So behavioural conformance has to run where
the credentials already are — the publisher's own CI — which makes it a
complement to TBOM rather than a competitor. Mine attaches through your
`attestations[]` and reuses ToolDigest unchanged.

One note on your scope question: a behavioural claim binds to a tool, not a
package. "Makes no network call" is true of one tool and false of the one next
to it. That pushed me to George's tool-scoped choice, even though you're right
about how packages ship.

Repo, if it's worth arguing with: https://github.com/vince-gonzalez/saydo —
proof of concept. Not claiming drift or hash-chained receipts as new; you were
there first and the repo says so.

@SamMorrowDrums — did that verification and provenance group ever form? Three
of us in this thread got to adjacent pieces of it independently, which seems
like the argument for one.

---

## Notes, not for the post

- ~250 words, down from ~600.
- Cut: the JCS paragraph, the coverage-model explanation, the two-run test.
  All true, none of it load-bearing for a first post. If he replies, they are
  the second post.
- Kept the self-own as the opener. It is the whole reason this reads as a
  report rather than a pitch, and it makes the point better than any claim
  about someone else's code.
- No measurements of named third-party servers. Our sweep ran with a broken
  sandbox, so those numbers are not trustworthy — and naming other people's
  servers in a first post picks a fight we don't want.
- 3,470 / 2,889 measured today, reproducible with `tools/discover_github.py`.
