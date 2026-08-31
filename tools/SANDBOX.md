# SayDo isolation and observation — the honest threat model

SayDo runs a tool to test it. That is unavoidable — behavior is only visible
at runtime — and it is also the central risk: running untrusted code to judge
it means executing it. This document states exactly what is observed, what is
enforced, and what is neither, so no receipt claims more than the setup earns.

## Two monitors, on purpose

**Boundary egress proxy** (`egress_proxy.py`). The server under test is
launched behind a logging HTTP/HTTPS proxy. Every request it makes through a
proxy-aware client passes through, and the proxy records the destination host
— including for HTTPS, whose `CONNECT` line names the host in the clear
without any decryption. This is language-agnostic: it caught a Node server's
egress (`grab -> example.com`) that the Python audit hook cannot see at all,
and it is the source of the egress hostnames in every Python server's receipt.

**CPython audit hook** (`monitor_boot/sitecustomize.py`). Injected via
PYTHONPATH, it observes the Python runtime: file opens, raw sockets,
subprocess spawns. It sees things the proxy cannot — a raw socket to a bare
IP that ignores proxy configuration (this is how the seeded fixture's
`fetch_quote` is still caught) — but only in Python.

Together they cover more than either alone. Neither is a sandbox.

## What is OBSERVED vs ENFORCED vs NEITHER

| behavior | observed | enforced | notes |
|---|---|---|---|
| HTTP/HTTPS egress via a proxy-aware client | yes, any language | no | proxy logs host; does not block |
| raw-socket egress from Python | yes | no | audit hook sees connect/getaddrinfo |
| raw-socket egress from a non-Python client | **no** | no | the real gap on this host |
| filesystem writes from Python | yes | no | audit hook |
| filesystem writes from a non-Python client | **no** | no | needs the container |
| subprocess spawn from Python | yes | no | audit hook |
| subprocess spawn from a non-Python client | **no** | no | needs the container |

The two **no**-observed rows are the honest limit, and they are why the next
architectural step is not optional.

## The measured gap that names the fix

Node's built-in `fetch` ignores proxy environment variables. Tested directly:
a default Node fetch to `example.com` returned 200 and the proxy saw nothing.
Only when the Node client explicitly routed through the proxy (undici
`ProxyAgent`) did the proxy record the egress. So on a host without network
isolation, a client that will not cooperate with proxy configuration, in a
language the audit hook cannot reach, escapes observation entirely.

This is not fixable by a better hook. It is fixed by **enforcement**: run the
server in a network namespace whose only route is the proxy, and a filesystem
mount it cannot escape. Then cooperation is irrelevant — there is no other
way out — and the observation becomes language-agnostic and complete. That
requires a Linux container host, which the Windows development machine is not.

## That fix is now demonstrated, not merely proposed (2026-08-29)

The enforcement claim is tested on every relevant push by
`.github/workflows/sandbox-enforcement.yml`, on a Linux runner with Docker,
because the claim is exactly the kind that should not be taken on trust.

The architecture: `saydo-inside` is an `--internal` Docker network, so a
container on it has no route off-host; `saydo-outside` is a normal bridge and
**only the proxy** is attached to it. The server's single reachable neighbour
is therefore the proxy, and the proxy is the single thing that can reach the
internet.

Results, from run 33280078992:

| case | expected | observed |
|---|---|---|
| non-cooperative client (Node `fetch`, **no** proxy config) | blocked | `BLOCKED Error: getaddrinfo EAI_AGAIN example.com` |
| cooperative client → allowlisted host | allowed | `STATUS 200` |
| cooperative client → host outside the allowlist | refused | `403 Forbidden` from the proxy |

The first row is the point. That is the *same* code path measured above
returning 200 on a host; inside the sandbox it cannot even resolve DNS. The
gap closes without the tool's cooperation, so it closes for every language.

**What this does and does not license.** It proves the mechanism works on
Linux. It does **not** retroactively make any existing receipt "contained":
every receipt in this repository was produced by the local runner, which
observes. `Runner.enforcement` carries the level from the run into the
receipt, so a receipt may only say contained when the run actually was.

## Closed: under enforcement, silence was ambiguous (2026-08-30)

The gap described below is fixed. The sandbox's only nameserver is now a sink
that records every query and answers NXDOMAIN, so a lookup that bypasses the
proxy is on the record before it is refused.

Measured in CI run 33298939994: the seeded server inside the sandbox now
scores `{pass: 1, fail: 5}` — the same five refutations the host run produces,
with `network.none` failing on `egress: fetch_quote->example.com`. Previously
that invariant passed, because the attempt died before anything watched fired.
Containment no longer costs attribution.

**The bare-IP case, and a correction.** The sink sees a tool that resolves a
hostname, which is essentially all ordinary code. It cannot see a tool that
connects to a bare IP, since there is no lookup to record.

The obvious fix — a kernel LOG rule on the sandbox bridge — was built, and it
does not work here. It installs correctly, and it records nothing, because on
an `--internal` network the container has no route off its own subnet: an
off-subnet connection fails in the routing table with `ENETUNREACH` and no
packet ever reaches the bridge. There is nothing to log. The rule is retained
because it is correct for a routed topology, but on this topology it adds no
coverage, and the monitor description says so rather than implying otherwise.

What actually attributes a bare-IP attempt is the in-container audit hook. A
literal address needs no resolution, so `socket.connect` fires and carries the
destination, and the harness now reports that address instead of discarding
it. Demonstrated: the seeded server's `beacon()` connects to `192.0.2.1`
(TEST-NET-1, RFC 5737, never routed) and is refuted by name.

**That boundary was language, not layer — and the routed topology removes it.**
Under the internal network a bare-IP attempt by a Python tool is recorded and
by a non-Python tool it is stopped invisibly. `--routed` closes that.

## The routed topology (2026-08-30)

The sandbox is given a gateway, so a bare-IP connection becomes a real packet
instead of dying in the routing table. The packet is logged on the bridge and
then dropped by a host firewall. Attribution stops depending on the tool's
language.

**The cost, stated because it is real:** containment now rests on those
firewall rules being correct, rather than on the absence of any route. Two
consequences are enforced in code rather than left to documentation:

- Routed mode **refuses to run** if the rules cannot be installed. A routed
  sandbox without its firewall has a working route to the internet, which
  would turn the safest part of this system into the most dangerous.
- The rules are **removed on teardown**, because a stale DROP on a recycled
  bridge name would silently break unrelated containers on the same host.

Isolated mode remains the default. The trade is opt-in, and `describe()`
states which topology a run used, so the sentence travels into the receipt.

**Measured, CI run 33303566208.** A Node tool — no Python, no name lookup —
connecting to `93.184.216.34:80`:

    containment   BLOCKED ETIMEDOUT ... OK: still contained
    attribution   SAYDO-EGRESS IN=br-3dace5f6e1f8 OUT=eth0 SRC=172.18.0.3
                  DST=93.184.216.34 PROTO=TCP DPT=80 SYN

Both halves, on the same attempt: it went nowhere, and we know exactly what it
tried. That is the case neither the DNS sink nor the Python audit hook can
see, and it is now covered.

## The original gap, kept for the record

A full conformance run of the seeded server inside the sandbox catches it
writing outside scope, spawning a child, returning non-deterministic output,
and raising instead of returning an error value. But `network.none` **passes**
there, while the *same server on a host fails it* with
`egress: fetch_quote->socket.connect`.

The tool did attempt egress both times. Inside the sandbox there is no DNS, so
`sock.connect(("example.com", 80))` fails during name resolution — which
CPython performs *before* it raises the `socket.connect` audit event. No
watched event fires, the harness sees nothing, and "nothing observed" is
rendered as a pass.

This is the correct verdict for the question actually asked ("did any egress
reach the boundary?") and a misleading answer to the question a reader has in
mind ("did this tool try to phone home?"). Enforcement without attribution
loses the more interesting fact: not that the tool failed, but that it tried.

Mitigated, not solved: an egress pass produced under enforcement now carries
an explicit note that it means no egress *reached* the boundary, not that none
was attempted. The real fix is to make attempts observable — run a logging DNS
resolver on the internal network and point the sandbox at it, so a name
lookup is recorded and refused rather than failing into silence. Until that
exists, read a contained `no-network` pass as "nothing got out", never as
"nothing was tried".

## The hardening roadmap this implies (in order)

1. **Container execution** (hosted service, Linux): each server in its own
   network + mount + pid namespace; only route is the proxy; resource and
   wall-clock limits; kill on breach. This turns every OBSERVED-only row into
   ENFORCED and closes both NEITHER rows.
2. **Egress policy at the proxy**: not just log the host, but refuse a host
   outside the declared allowlist, and record the refusal in the receipt.
3. **Filesystem policy**: a scratch mount per run; a write outside it fails
   at the OS, not just in the report.

   With one deliberate exception, measured. A read-only root also denied
   servers the state directory they create under `$HOME` before they will
   serve at all, and four servers in the corpus sweep died in their own
   constructor because of it — then got filed under *their* failures, which is
   a harness marking its own bug as the ecosystem's. The sandbox now mounts an
   ephemeral `tmpfs` home (`noexec`, `nosuid`, 32 MB, destroyed at teardown).

   Both mounts are `mode=1777`, and `TMPDIR` points at the scratch. This is
   not incidental. The containers run as an unprivileged user (uid 10001) and
   a tmpfs defaults to root-owned `0755`, so **the sandbox had no writable
   path at all**: `tempfile.gettempdir()` walked `/tmp`, `/var/tmp`,
   `/usr/tmp` and `/scratch`, was refused by every one, and raised
   `FileNotFoundError: No usable temporary directory found`. Any server that
   touches a temporary file — a large share of them — died before it could do
   anything, and the failed probes were recorded as *the tool attempting
   writes*. Every contained run before this fix was measuring a program that
   could not write, and reporting the result as the program's behaviour.

   The trade, stated plainly: the tool can now write in two places instead of
   one, and neither survives the run or reaches the host. Writes to the home
   are **not** exempt from the report — they are recorded and judged against
   the declared write scope exactly like any other write. CI asserts this
   directly: the seeded server writes into the sandbox home on purpose, and if
   that write ever stops appearing in the findings the job fails. A permitted
   write is fine; an unobserved one is the thing this whole layer exists to
   prevent.
4. **Least privilege for SayDo itself**: pinned dependencies, its own releases
   signed by SayDo, the signing key managed (not the proof-of-concept key in
   `keys/`).

## OPEN: a Node MCP server cannot be measured at all (2026-08-31)

Measured, not suspected. The seven official reference servers were run in the
sandbox four times. Every Python one produced verdicts. Every Node one produced
`not-covered` across the board, with the honest reason attached: *no monitor
event of any kind was recorded during this run, so there was no observation
channel.*

There are three channels and none of them reaches a Node server:

| channel | Python | Node |
|---|---|---|
| in-process audit hook | yes | **no** — `sys.addaudithook` is CPython-only |
| recording proxy | yes | only if a packet is actually emitted |
| bind-mounted scratch | yes | only if the server writes *there* |

The last two look like they should help and do not, for reasons specific to
these servers rather than to the design. `server-memory` writes its JSON graph
beside its own module, not into the scratch. `server-filesystem` takes its
allowed directories as argv and was given none. `everything` and
`sequential-thinking` are pure computation and touch nothing. So there is
nothing for a proxy or a filesystem watcher to catch, and the harness correctly
declines to score silence it cannot interpret.

Three fixes were tried and none of them addressed this:

- **routed containment** makes a network attempt attributable in any language.
  Real, and irrelevant here: these servers make no network calls.
- **`docker diff`** cannot see a tmpfs, and both writable paths were tmpfs. It
  was incapable of returning anything, in any run.
- **a bind-mounted scratch** gives the tool a real place to write and lets the
  host read it back. Also real, and also irrelevant unless the server happens
  to write there.

**The fix is a Node-side monitor**: a `--require` preload that hooks `fs`,
`net`, `dns` and `child_process` and reports on the same stderr channel the
Python hook uses, so the harness needs no new ingestion path. That is a real
piece of work, not a flag, and it is not done.

**Until it is, SayDo measures Python MCP servers.** A Node server gets
`not-covered` with the reason stated, which is honest and useless, and no
corpus that includes them says anything about them. That belongs in any figure
this project publishes: a sweep is a measurement of the Python half of the
ecosystem and must be reported as such.

## What a receipt may and may not say today

May say: what the monitors observed stayed inside the declared envelope, for a
proxy-aware or Python tool, and the record is tamper-evident and signed.

May not say: the tool was contained, or that a determined tool could not have
acted unobserved. Until enforcement (step 1) lands, a green receipt is
evidence of good behavior on the observed paths, not proof that no other path
was available. The receipt's `monitor` field states this in every receipt.
