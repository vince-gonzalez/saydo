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
requires a container host (Linux namespaces / seccomp), which is the
deployment target for the hosted service and is not available on the current
Windows build.

## The hardening roadmap this implies (in order)

1. **Container execution** (hosted service, Linux): each server in its own
   network + mount + pid namespace; only route is the proxy; resource and
   wall-clock limits; kill on breach. This turns every OBSERVED-only row into
   ENFORCED and closes both NEITHER rows.
2. **Egress policy at the proxy**: not just log the host, but refuse a host
   outside the declared allowlist, and record the refusal in the receipt.
3. **Filesystem policy**: a scratch mount per run; a write outside it fails
   at the OS, not just in the report.
4. **Least privilege for SayDo itself**: pinned dependencies, its own releases
   signed by SayDo, the signing key managed (not the proof-of-concept key in
   `keys/`).

## What a receipt may and may not say today

May say: what the monitors observed stayed inside the declared envelope, for a
proxy-aware or Python tool, and the record is tamper-evident and signed.

May not say: the tool was contained, or that a determined tool could not have
acted unobserved. Until enforcement (step 1) lands, a green receipt is
evidence of good behavior on the observed paths, not proof that no other path
was available. The receipt's `monitor` field states this in every receipt.
