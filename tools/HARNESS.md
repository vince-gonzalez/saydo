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
