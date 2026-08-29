# The container build — scope, state, and what it changes

The one move that converts SayDo from a monitor into an enforcer, and from
Python-plus-cooperative-clients to every language. Written down because the
build spans a host this machine cannot provide.

## Why (the measured reason, not a preference)

On a host, SayDo OBSERVES. The proxy sees egress a client chooses to route
through it; the audit hook sees Python. Measured in SANDBOX.md: Node's default
`fetch` ignores proxy configuration entirely, so a non-cooperating client in a
non-Python language escapes observation. No better hook fixes that.

In a container whose only network route is the SayDo proxy and whose only
writable path is a scratch tmpfs, cooperation is irrelevant -- there is no
other way out. The same boundary then covers every language, and a receipt
can honestly say *contained* rather than *observed*.

## Decisions taken

- **Host:** a free-tier Linux VM (Oracle Always-Free / GCP e2-micro). ~$0, and
  it is the same surface the hosted service would later use.
- **Isolation:** gVisor (`runsc`) as the Docker runtime. Not either/or: gVisor
  is a `--runtime` flag on the same `docker run`, so the locked-down Docker
  path and the hardened path are one implementation. If gVisor will not install
  on the chosen VM (ARM or nested-virt quirks), the Docker path still stands
  and the runner simply omits the flag.

## State

Built and testable here:

- `tools/runner.py` — `LocalRunner` (today's behavior) and `ContainerRunner`
  (docker + optional runsc, read-only rootfs, tmpfs scratch, `--cap-drop ALL`,
  no-new-privileges, pid/memory limits, internal network). `available()`
  reports honestly whether a host can run it; `make()` refuses an unknown
  runner rather than silently downgrading to observation.
- `tools/egress_proxy.py` — allowlist ENFORCEMENT. `allow=None` stays
  observe-only (honest on a host, where a tool can route around anyway);
  `allow={hosts}` refuses anything else with 403 and records
  `proxy.refused`. **Verified on this machine:** an allowlisted host connects,
  a non-allowlisted host is refused and logged.
- `container/Dockerfile.python`, `container/Dockerfile.node` — per-server
  images, pinned `SERVER_SPEC`, non-root user, no credentials, no host mounts.
- `container/provision.sh` — one-shot host setup: Docker, gVisor, and the
  `--internal` network that makes "no route out except the proxy" true.

Cannot be validated here: anything that actually runs a container. This
machine has no Docker and no WSL. That is the gate.

## Remaining steps, in order

1. **[owner]** Create the free-tier VM; run `provision.sh`; give the harness a
   way to reach it (SSH, or run the harness on the VM).
2. Wire `ContainerRunner` into `harness.Run` behind an explicit `--runner`
   choice; keep `local` the default until the container path is proven.
3. Attach the proxy to the `saydo-none` network so it is the containers'
   only reachable host; pass the declaration's allowlist into `allow=`.
4. Write-scope enforcement: `/scratch` is the declared write scope; a write
   elsewhere fails at the OS. Replace the audit hook's write observation with
   a mount diff.
5. Prove enforcement, the same way the harness proved itself:
   - the seeded fixture's egress is BLOCKED, not merely recorded;
   - the non-cooperative Node client (default `fetch`, no proxy config) is
     caught -- the case that escapes today;
   - a write outside `/scratch` fails;
   - `mcp-server-git`'s subprocess is still seen via the pid namespace.
6. Only then let receipts say "contained": `Runner.enforcement` feeds the
   receipt's `monitor` field, so the claim tracks how the run actually
   happened. A local run must keep saying "observed".

## What must not happen

No receipt may claim containment for a run that used `LocalRunner`. The
enforcement level is a property of the run, carried from the runner into the
receipt, never a default and never assumed. Step 6 exists so the claim cannot
drift ahead of the mechanism.
