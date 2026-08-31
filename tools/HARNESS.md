# Conformance harness — how it decides

The harness turns a behavioral declaration into a conformance report: one
verdict per declared invariant, plus any finding the declaration did not
anticipate. It is the CONFORMANCE layer of the four; it consumes a
declaration and a capture, exercises the released server under observation,
and judges what it sees.

## The pieces

    monitor_boot/sitecustomize.py   a CPython audit hook, injected via
                                    PYTHONPATH, that records the server's file
                                    opens, socket activity, and subprocess
                                    spawns as JSON lines
    mcp_client.py                   a from-scratch MCP stdio client that
                                    reports exactly what the transport did:
                                    result / rpc-error / died / timeout
    plans.py                        per-server exercise plans, the fuzz pools,
                                    and the property checks
    harness.py                      launches, exercises, attributes events to
                                    calls, and emits verdicts
    seeded/malserver.py             a server that violates its own declaration
                                    on purpose; the harness must catch it

## The three-valued verdict

    pass          an observation window existed and nothing in it contradicts
                  the invariant
    fail          an observation contradicts the invariant
    not-covered   no window existed, or the check is not implemented

`not-covered` is never upgraded to `pass`. A tool the plan did not exercise
gets `not-covered`, not a green check it did not earn. A server is reported
conformant only when there are zero findings, zero fails, and at least one
pass — so an all-not-covered run is not conformance.

## A negative claim needs conduct, not silence

An invariant of the form *it does not do X* — `no-network`, `no-write`,
`no-subprocess`, `write-scope`, `read-scope` — can only pass if the run
observed the tool **doing something**. If no call window produced any
observable effect, all of them come back `not-covered` with the reason
attached.

This is not a refinement. Without it, a server that starts, lists its tools and
declines every call satisfies every negative invariant at once and collects a
signed receipt reading CONFORMANT. That server made no network request the way
an unplugged machine makes none. It is also, by a wide margin, the commonest
server in the public sweep, so the rule decides what the mark means for most of
the population rather than for a corner case.

A `refusal-tool` pass does not count as conduct. The server answering a
question about itself is not the server behaving, and a warrant that rests on
it is a warrant the subject issued to itself. The report carries `established`
— passes about conduct — beside `conformant`, which only ever meant *nothing
failed*, and nothing fails in a run where nothing happened.

**Computing counts as acting.** A tool can do real work without touching
anything. `mcp-server-time` returns a different, correct answer for
`America/New_York` than for `Asia/Tokyo`, opens no socket and writes no file.

So every tool is called twice, with DIFFERENT valid arguments, and an answer
that changes with the input is proof the tool computed. This is the egress
counterfactual pointed at coverage instead: intervene on the input and see
whether the output follows.

It has to be this rather than "did the call succeed", because a server that
declines every call also succeeds — it returns the same refusal whatever you
ask. Varying the input separates the two without reading the content of either
answer.

This paragraph used to say the opposite. It called the syscall requirement a
limitation affecting pure-calculation tools, which was wrong twice over: those
are most well-written tools, and the harness was establishing nothing about any
of them while that was reported as a fact about the ecosystem.
`mcp-server-time` — official, credential-free, entirely cooperative — returned
four `not-covered` verdicts until this was fixed.

## What the monitor can and cannot do

It observes the Python runtime through the audit hook: it sees `open`,
`socket.*`, `subprocess.*`, and the filesystem-mutating `os.*`/`shutil.*`
calls. It does NOT see past the runtime — code that calls the OS through
ctypes or a native extension built to evade is invisible to it. So the honest
claim, stated in every report, is: this catches drift, accidents, and
ordinary misbehavior, and refutes false declarations made by ordinary code.
It is not a sandbox. No receipt calls it one.

Two observations are deliberately excluded as runtime housekeeping rather than
tool behavior: reads of the interpreter's own stdlib and site-packages (a
tool's first call lazily imports; that is the interpreter, not the tool
reaching into the world), and bytecode writes (turned off via
PYTHONDONTWRITEBYTECODE so they cannot be mistaken for the tool writing).

**The monitor stream is checked for holes.** In a container the hook reports
over stderr, and the reader used to swallow both an unparseable line and any
exception in its loop — so a single provoked error stopped the watching for the
rest of the run, and the harness went on to report that the tool had performed
no writes. Unreadable lines are now counted and a stream that ends early keeps
the reason; any invariant resting on those observations then returns
`not-covered`, never `pass`. Fails are not withdrawn, because an event that
arrived really happened. A monitor that can be silenced is a problem. A monitor
that can be silenced and then issues a clean verdict is worse than none.

## Event attribution

Calls on one session are sequential. Each monitor event is attributed to the
single call that had started when it fired, bounded by the next call's start,
so one `subprocess.Popen` is blamed on exactly the tool that spawned it. An
earlier version gave every window a 0.25 s slop; overlapping windows smeared
every event across every tool, and the seeded server's one honest tool was
wrongly convicted. The fix — exclusive windows — is why the seeded run now
reads as five specific violations and one clean tool.

## Verify the verifier

`seeded/malserver.py` ships a declaration claiming the clean envelope every
real server claims — no network, no writes, no subprocess, determinism,
error-as-value — and then each tool breaks one claim: `fetch_quote` opens a
socket, `save_note` writes outside scope, `run_helper` spawns a child, `roll`
returns a counter, `lookup` raises. `scope` is left honest, so the harness
must ALSO produce a true pass and not simply reject everything.

Required result: `conformant=False`, one pass (scope), five fails, each
attributed to the right tool and the right invariant. If the harness ever
reports the seeded server conformant, or mislabels which invariant each
violation broke, the harness is broken and no report it produces is worth
anything.

`seeded/silentserver.py` tests the opposite failure, and it is the one the
harness actually had. It starts, lists three tools, and answers every call with
*not configured* — doing nothing at all. Required result: **INCONCLUSIVE**,
every negative invariant `not-covered`, `established=0`, and a registry state
of `inconclusive` whose badge reads "checked, but nothing was established".

When it was written, the harness reported that server **CONFORMANT** and signed
the receipt. Two fixtures are needed because there are two ways to be wrong: a
harness that misses a tool doing something it promised not to, and a harness
that credits a tool for not doing anything at all. The second is the easier
mistake to make and the harder one to notice, because everything looks green.

Both are asserted in CI, on the library (`saydo selfcheck`) and on the Action
(`.github/workflows/action-selfcheck.yml`): a build must fail on a tool that
lies, and on a run that shows nothing.

## Findings the harness surfaced about its own subjects

- remapwrap's `build_board` / `build_mixer` allocate control ids from a
  process-global counter, so byte output depends on call history. Functionally
  harmless — the layout is identical — but it means strict determinism is
  false, and the declaration scopes the claim with `volatile: ["id"]` rather
  than over-claiming. The counter carrying process state into tool output is a
  real observation to hand to the maintainer.
- Several authorecon tools let exceptions reach the transport, so
  `error-as-value` is not declared for that server (the other four wrap
  errors into the result payload).

## Run one

    python harness.py <declaration.json> <capture.json> <report.json> \
        --python <interpreter-that-runs-the-server>

`--plan <name>` overrides the plan when the subject name is not the plan key
(used for the seeded server).
