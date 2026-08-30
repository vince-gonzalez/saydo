"""The conformance harness: exercise a server, judge it against its declaration.

Produces a conformance report: one verdict per declared invariant, plus any
findings the declaration did not anticipate. Verdicts are three-valued and
refusal-first:

    pass         an observation window existed and nothing in it contradicts
                 the invariant
    fail         an observation contradicts the invariant
    not-covered  no window existed, or the check is not implemented here

not-covered is never silently upgraded to pass. An invariant the harness
cannot exercise is reported as unproven, because a green check the harness
did not earn is the exact dishonesty this project refuses.

Pipeline per run:
  1. Recompute the tool-definition digests from the live tools/list and
     compare to the binding. A mismatch or a surface mismatch is a finding
     and the behavioral run does not lend those tools any warrant.
  2. Exercise the server under the injected monitor: valid calls, chained
     calls, determinism replays, and (where declared) error-as-value fuzzing.
  3. Attribute every monitor event to the invariants covering the tool whose
     call window it falls in.
  4. Emit verdicts.

Usage:
    python harness.py <declaration.json> <capture.json> <report.json> \
        --python <interpreter-for-the-server>
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import time
from urllib.parse import urlsplit

import jcs
import plans as plans_mod
from mcp_client import Session


def _read_events(log_path):
    events = []
    if not os.path.exists(log_path):
        return events
    with open(log_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except ValueError:
                    pass
    return events


def _resolved_host(event):
    """The hostname a getaddrinfo asked to resolve, or None.

    The audit event 'socket.getaddrinfo' carries (host, port, family, type,
    protocol), so the hostname is args[0]. This is the right signal for a
    hostname allowlist: it is the name the tool's code asked for, before DNS
    turned it into an address. socket.connect carries only the resolved IP
    (in args[1], the address; args[0] is the socket object), which cannot be
    mapped back to a name reliably, so connect is used only to detect that
    egress happened at all, never to name the host.
    """
    if event["event"] == "socket.getaddrinfo":
        args = event.get("args") or []
        host = args[0] if args else None
        return host if isinstance(host, str) else None
    if event["event"] == "bridge.attempt":
        # A connection the sandbox network dropped, recorded on its way out.
        # There is no name to report -- the tool never asked for one -- so the
        # destination address is the identity.
        host = event.get("host")
        return host if isinstance(host, str) else None
    if event["event"] == "socket.connect":
        # The address the socket was pointed at. For a literal IP there is no
        # lookup to record anywhere else, so this is the ONLY place the
        # destination appears -- discarding it would throw away the single
        # piece of attribution available for a bare-IP connection.
        args = event.get("args") or []
        addr = args[1] if len(args) > 1 else None
        ip = addr[0] if isinstance(addr, list) and addr else None
        return ip if isinstance(ip, str) else None
    if event["event"] == "dns.query":
        # A recorded lookup is an ATTEMPT. Inside the sandbox it was refused,
        # but the tool asking the question is the fact worth keeping: it is
        # what distinguishes "was prevented" from "never tried".
        host = event.get("host")
        return host if isinstance(host, str) else None
    if event["event"] in ("proxy.connect", "proxy.refused"):
        # The boundary proxy records the real destination host of an HTTP or
        # HTTPS connection, whatever language made it. This is the primary
        # egress signal: once the server is launched behind the proxy, its
        # own DNS resolves the proxy (loopback), so the in-runtime hook no
        # longer sees the real host -- the proxy does.
        host = event.get("host")
        return host if isinstance(host, str) else None
    return None


NET_EVENTS = {"socket.connect", "socket.getaddrinfo", "socket.bind",
              "socket.sendto", "proxy.connect", "proxy.refused", "dns.query",
              "bridge.attempt"}
#: Events that name a destination the tool ASKED for, whether or not it got
#: there. An allowlist is judged on these, since a refused or unresolved
#: attempt still tells you what the tool wanted.
NAMED_ATTEMPT_EVENTS = {"socket.getaddrinfo", "proxy.connect", "proxy.refused",
                        "dns.query", "bridge.attempt"}
PROC_EVENTS = {"subprocess.Popen", "os.system", "os.exec", "os.spawn",
               "os.posix_spawn"}
WRITE_EVENTS = {"os.remove", "os.rename", "os.mkdir", "os.rmdir",
                "os.truncate", "os.link", "os.symlink", "shutil.rmtree",
                "shutil.copyfile", "shutil.move"}


class Run:
    """One launch of the server, its call windows, and its monitor events."""

    def __init__(self, name, plan, server_python, monitor_log,
                 egress_log=None, runner=None):
        self.name = name
        self.windows = []   # (tool, t0, t1, outcome)
        self.events = []
        self.egress_log = egress_log
        self.runner = runner
        self._launch(plan, server_python, monitor_log)

    def _command(self, plan, server_python):
        base = _launch(plan, server_python)
        if self.runner:
            return self.runner.argv(plan, server_python, base)
        return base

    def _launch(self, plan, server_python, monitor_log):
        # The proxy's log accumulates across runs, so a run must know when it
        # began. Without this, a canary planted in an earlier run is still in
        # the log during a later one and reads as the tool having RETAINED
        # input across calls -- a serious accusation, and false.
        self.started = time.time()
        open(monitor_log, "w").close()
        env = {}
        appdata = None
        if plan.get("appdata_sandbox"):
            appdata = tempfile.mkdtemp(prefix="saydo-appdata-")
            env["APPDATA"] = appdata
        self.appdata = appdata
        timeout = plan.get("call_timeout", 60)

        # A containerised server cannot write to a host log path, so its audit
        # hook is enabled inside the image and reports over stderr instead.
        # The hook stays ON either way: enforcement stops a tool from
        # succeeding, but only the hook shows that it TRIED. Silence would not
        # distinguish "never attempted" from "attempted and was prevented",
        # and the second is the more interesting fact about a tool.
        containerised = bool(self.runner
                             and self.runner.enforcement == "contained")
        session = Session(self._command(plan, server_python), env=env,
                          monitor_log=None if containerised else monitor_log)
        self._session = session
        try:
            init = session.initialize()
            if init.kind != "result":
                self.init_failure = init.kind
                return
            self.init_failure = None
            for tool, args, _det in plan["exercise"]:
                out = session.call(tool, args, timeout)
                self.windows.append((tool, out.t0, out.t1, out))
            self._run_chain(session, plan, timeout)
        finally:
            session.close()
            time.sleep(0.3)   # let the proxy flush the tunnel's CONNECT line
            self.events = _read_events(monitor_log)
            # In-container hook events arrive over stderr rather than a file.
            self.events += list(getattr(session, "monitor_events", []))
            # Merge the boundary-proxy egress into the same event stream; both
            # are {t, event, host}, so attribution by call window is identical
            # whether the proxy was a local listener or a container.
            if self.runner:
                self.events += self.runner.collect_egress()
            elif self.egress_log:
                self.events += _read_events(self.egress_log)

    def _run_chain(self, session, plan, timeout):
        produced = {tool: out for tool, _t0, _t1, out in self.windows}
        for step in plan.get("chain", []):
            src = produced.get(step["from"])
            if not src:
                continue
            payload = src.payload() or {}
            value = payload.get(step["take"])
            if value is None:
                continue
            args = {step["arg"]: value}
            args.update(step.get("extra", {}))
            out = session.call(step["tool"], args, timeout)
            self.windows.append((step["tool"], out.t0, out.t1, out))

    def _attribute(self):
        """Assign each monitor event to exactly one call window.

        Calls on one session are sequential, so an event belongs to the last
        call that had started when it fired -- bounded so idle-time events
        between calls are attributed to nothing. A single shared boundary
        (the next call's start) is what keeps one Popen from being blamed on
        every tool; the earlier 0.25s-per-window slop overlapped windows and
        smeared every event across all of them.
        """
        by_window = {i: [] for i in range(len(self.windows))}
        starts = [w[1] for w in self.windows]
        for ev in self.events:
            t = ev["t"]
            idx = None
            for i in range(len(self.windows)):
                if starts[i] <= t:
                    nxt = starts[i + 1] if i + 1 < len(starts) else float("inf")
                    end = self.windows[i][2] + 0.05
                    if t < nxt and t <= max(end, nxt - 1e-9):
                        idx = i
                else:
                    break
            if idx is not None:
                by_window[idx].append(ev)
        self._by_window = by_window

    def events_for(self, tool):
        if not hasattr(self, "_by_window"):
            self._attribute()
        for i, (t, _t0, _t1, _out) in enumerate(self.windows):
            if t == tool:
                for ev in self._by_window[i]:
                    yield ev

    def outcomes_for(self, tool):
        return [out for t, _t0, _t1, out in self.windows if t == tool]


def _tools_of(invariant, bound_names):
    applies = invariant["appliesTo"]
    return sorted(bound_names) if applies == ["*"] else applies


def _self_read_ok(path, ctx):
    """A read the invariant permits regardless: the tool's own code, the
    interpreter's runtime, declared alsoAllowed paths."""
    if not path or not isinstance(path, str):
        # A non-string target is a file-descriptor open (framework internals),
        # not a filesystem path the tool chose. Nothing to attribute.
        return True
    p = os.path.normcase(os.path.abspath(path))
    for root in ctx["runtime_roots"]:
        if p.startswith(os.path.normcase(root)):
            return True
    return False


def judge(declaration, capture, run, ctx):
    findings = []           # unanticipated: drift, surface, crashes
    verdicts = []           # per invariant

    bound = {t["name"]: t for t in declaration["binding"]["tools"]}
    live = {t["name"]: t for t in capture["tools"]}

    # 1. Binding: digests and surface.
    for name in sorted(set(live) - set(bound)):
        findings.append({"kind": "undeclared-surface", "tool": name,
                         "detail": "served live, not in the declaration"})
    for name in sorted(set(bound) - set(live)):
        findings.append({"kind": "missing-tool", "tool": name,
                         "detail": "declared, not served live"})
    for name in sorted(set(bound) & set(live)):
        recomputed = jcs.digest(live[name]["definition"])
        stated = bound[name]["definitionDigest"]["value"]
        if recomputed != stated:
            findings.append({"kind": "definition-drift", "tool": name,
                             "detail": "declared {} but live definition hashes "
                                       "to {}".format(stated, recomputed)})

    drifted = {f["tool"] for f in findings
               if f["kind"] in ("definition-drift", "undeclared-surface")}
    bound_names = set(bound)

    def window_ran(tools):
        return any(run.outcomes_for(t) for t in tools)

    for inv in declaration["invariants"]:
        tools = _tools_of(inv, bound_names)
        vtype = inv["type"]
        params = inv.get("params") or {}
        row = {"id": inv["id"], "type": vtype, "appliesTo": inv["appliesTo"]}

        # A drifted tool lends no warrant to its behavioral invariants.
        if drifted.intersection(tools):
            row["verdict"] = "not-covered"
            row["evidence"] = ("covers a tool whose definition drifted from "
                               "the binding; behavior not warranted")
            verdicts.append(row)
            continue

        if vtype == "refusal-tool":
            tool = params.get("tool")
            outs = run.outcomes_for(tool)
            listed = tool in live
            answered = any(o.kind == "result" for o in outs)
            # "No I/O" means none on the user's behalf: no network, no
            # subprocess, no writes, and no reads outside the interpreter's
            # own runtime files. A first call that lazily imports stdlib is
            # the interpreter's housekeeping, not the tool touching the world.
            observable = []
            for ev in run.events_for(tool):
                if ev["event"] in NET_EVENTS or ev["event"] in PROC_EVENTS \
                        or ev["event"] in WRITE_EVENTS:
                    observable.append(ev["event"])
                elif ev["event"] == "open":
                    if ev.get("intent") == "write":
                        observable.append("write:" + str(ev.get("path")))
                    elif not _self_read_ok(ev.get("path"), ctx):
                        observable.append("read:" + str(ev.get("path")))
            no_io = not observable
            ok = listed and answered and no_io
            row["verdict"] = "pass" if ok else "fail"
            row["evidence"] = ("{} listed={} answered={} did_no_io={}{}"
                               .format(tool, listed, answered, no_io,
                                       "" if no_io else " io=" + ";".join(
                                           observable[:4])))

        elif vtype in ("no-network", "network-allowlist"):
            allowed = set(params.get("hosts", []))
            hits = []
            observed = set()
            for tool in tools:
                for ev in run.events_for(tool):
                    if ev["event"] not in NET_EVENTS:
                        continue
                    host = _resolved_host(ev)
                    # The loopback route to the boundary proxy is the monitored
                    # path, not egress; the proxy.connect event carries the real
                    # destination for anything that went through it.
                    if host and _loopback(host):
                        continue
                    if ev["event"] == "socket.connect" and _connect_loopback(ev):
                        continue
                    if host:
                        observed.add(host)
                    if vtype == "no-network":
                        # Any egress at all refutes the claim. A named host
                        # (from the proxy or a direct resolve) or an
                        # unnameable raw connect both count.
                        hits.append((tool, host or ev["event"]))
                    elif ev["event"] in NAMED_ATTEMPT_EVENTS:
                        # Allowlist judges by the destination NAME, from the
                        # proxy, a direct getaddrinfo, or a recorded lookup.
                        if host and host not in allowed:
                            hits.append((tool, host))
                    elif ev["event"] in ("socket.connect", "socket.sendto"):
                        # A raw connection carries an address, not a name, so
                        # it cannot be checked against a hostname allowlist.
                        # Unverifiable is not the same as permitted: report it
                        # rather than let it pass unexamined.
                        hits.append((tool, "raw connection to {} (an address "
                                            "cannot be checked against a "
                                            "hostname allowlist)"
                                     .format(host or "an unnamed peer")))
            windows = sum(1 for t in tools for _ in run.outcomes_for(t))
            if not window_ran(tools):
                row["verdict"] = "not-covered"
                row["evidence"] = "no call window for the covered tools"
            elif hits:
                row["verdict"] = "fail"
                seen = []
                for t, h in hits:
                    if (t, h) not in seen:
                        seen.append((t, h))
                row["evidence"] = "egress: " + "; ".join(
                    "{}->{}".format(t, h) for t, h in seen[:8])
            else:
                row["verdict"] = "pass"
                obs = ", ".join(sorted(observed)) if observed else "no hosts"
                row["evidence"] = ("resolved {} across {} call window(s); all "
                                   "within the declared set".format(obs, windows)
                                   if allowed else
                                   "{} resolved across {} call window(s)"
                                   .format(obs, windows))
                if ctx.get("enforcement") == "contained" and not observed:
                    # Under enforcement, silence is ambiguous. A tool that
                    # bypasses the proxy with a raw socket fails at DNS before
                    # any watched event fires, so "nothing observed" can mean
                    # "was prevented" rather than "never tried" -- and those
                    # are very different facts about a tool. Say so rather
                    # than letting the pass imply good behaviour.
                    row["evidence"] += (
                        "; NOTE: egress was enforced at the boundary, so an "
                        "attempt that failed before reaching it is not "
                        "individually attributable. This pass means no egress "
                        "reached the boundary, NOT that none was attempted.")

        elif vtype == "no-data-egress":
            # The strongest claim a tool can make and the strongest finding
            # SayDo can produce: not that a call happened, but that the tool's
            # own input left, and to where.
            matches, unexamined, clean = [], [], 0
            for tool in tools:
                for ev in run.events_for(tool):
                    name = ev.get("event", "")
                    if name == "exfil.match":
                        matches.append((tool, ev.get("host"), ev.get("detail")))
                    elif name == "exfil.unexamined":
                        unexamined.append((tool, ev.get("host")))
                    elif name == "exfil.clean":
                        clean += 1
            table = ctx.get("differential") or {}
            if matches:
                row["verdict"] = "fail"
                row["evidence"] = "the tool sent its own input data out: " + \
                    "; ".join("{} -> {}".format(t, h) for t, h, _ in matches[:5])
                # The causal reading, which observation alone cannot supply.
                # Both classes are reported: naming the destinations that do
                # NOT carry the input is what stops this being another alarm
                # that flags every outbound connection.
                if table:
                    row["evidence"] += (
                        ". Established by changing the input between runs: "
                        + "; ".join("{} is {}".format(h, v["relation"])
                                    for h, v in sorted(table.items())))
            elif unexamined:
                # Refusal-first, and the case that matters most: an opaque
                # payload is not evidence of innocence. Reporting this as a
                # pass would be exactly the lie this project exists to stop.
                row["verdict"] = "not-covered"
                row["evidence"] = (
                    "{} payload(s) could not be decoded, so whether data left "
                    "is UNKNOWN: {}".format(
                        len(unexamined),
                        "; ".join("{} -> {}".format(t, h)
                                  for t, h in unexamined[:5])))
            elif clean:
                row["verdict"] = "pass"
                row["evidence"] = ("{} outbound payload(s) examined in full, "
                                   "none carried the tool's input".format(clean))
                # A tool can be innocent of exfiltration and still talk to a
                # server on every call. Saying which is which is the useful
                # part: it turns "it made a call" into a characterisation.
                import differential
                independent = [h for h, v in table.items()
                               if v["relation"] == differential.INPUT_INDEPENDENT]
                if independent:
                    row["evidence"] += (
                        ". Contact with {} persisted when the input changed, "
                        "so that egress is independent of what the tool is "
                        "given -- a fixed backend, not exfiltration"
                        .format(", ".join(sorted(independent)[:4])))
            else:
                row["verdict"] = "not-covered"
                row["evidence"] = ("no outbound payload was examined; content "
                                   "inspection requires the container runner")

        elif vtype == "no-subprocess":
            hits = [(tool, ev["event"]) for tool in tools
                    for ev in run.events_for(tool)
                    if ev["event"] in PROC_EVENTS]
            row.update(_binary_verdict(window_ran(tools), hits, "subprocess"))

        elif vtype == "no-write":
            hits = [(t, p) for t, p, _d in _write_hits(run, tools, ctx)]
            row.update(_binary_verdict(window_ran(tools), hits, "write"))

        elif vtype == "write-scope":
            roots = [_expand(p, ctx) for p in params.get("paths", [])]
            hits = []
            for tool, path, is_dir in _write_hits(run, tools, ctx):
                if _under_any(path, roots):
                    continue
                # Creating a directory that must exist for an in-scope path
                # (an ancestor of the scope, e.g. makedirs building the tree)
                # is not a write outside scope; a FILE outside scope is.
                if is_dir and _ancestor_of_any(path, roots):
                    continue
                hits.append((tool, path))
            row.update(_binary_verdict(window_ran(tools), hits,
                                       "out-of-scope write"))

        elif vtype == "read-scope":
            extra = [_expand(p, ctx) for p in params.get("alsoAllowed", [])]
            arg_paths = _declared_arg_paths(run, tools, params, ctx)
            hits = []
            for tool in tools:
                for ev in run.events_for(tool):
                    if ev["event"] == "open" and ev.get("intent") == "read":
                        path = ev.get("path")
                        if _self_read_ok(path, ctx):
                            continue
                        if _under_any(path, extra) or path in arg_paths \
                                or _under_any(path, arg_paths):
                            continue
                        hits.append((tool, path))
            row.update(_binary_verdict(window_ran(tools), hits,
                                       "out-of-scope read"))

        elif vtype == "error-as-value":
            row.update(_judge_error_as_value(declaration, run, tools, ctx))

        elif vtype == "deterministic":
            row.update(_judge_determinism(inv, tools, ctx))

        elif vtype == "property":
            row.update(_judge_property(inv, ctx))

        else:
            row["verdict"] = "not-covered"
            row["evidence"] = "no harness support for type " + vtype

        verdicts.append(row)

    # Crashes seen anywhere are findings even when no invariant covered them.
    for tool, _t0, _t1, out in run.windows:
        if out.kind == "died":
            findings.append({"kind": "server-died", "tool": tool,
                             "detail": "process exited during this call "
                                       "(exit {})".format(out.exit_code)})
    return verdicts, findings


def _loopback(host):
    return host in ("127.0.0.1", "::1", "localhost") or \
        (isinstance(host, str) and host.startswith("127."))


def _connect_loopback(ev):
    """A socket.connect whose address is loopback (e.g. the boundary proxy)."""
    args = ev.get("args") or []
    addr = args[1] if len(args) > 1 else (args[0] if args else None)
    ip = addr[0] if isinstance(addr, list) and addr else addr
    return isinstance(ip, str) and _loopback(ip)


def _binary_verdict(ran, hits, label):
    if not ran:
        return {"verdict": "not-covered",
                "evidence": "no call window for the covered tools"}
    if hits:
        shown = "; ".join("{}:{}".format(t, x) for t, x in hits[:6])
        return {"verdict": "fail", "evidence": "{}: {}".format(label, shown)}
    return {"verdict": "pass", "evidence": "no {} observed".format(label)}


_DIR_EVENTS = {"os.mkdir", "os.rmdir"}
_NULL_DEVICES = {"nul", "con", "/dev/null", "/dev/zero"}


def _is_null_device(path):
    """A write to the null device persists nothing and is not a filesystem
    write. subprocess.DEVNULL opens 'nul' on Windows, so counting it would
    misfire on any tool that redirects a child's output to the bit bucket."""
    if not isinstance(path, str):
        return False
    p = path.replace("\\", "/").lower()
    base = p.rsplit("/", 1)[-1]
    return p in _NULL_DEVICES or base in _NULL_DEVICES or p.endswith("/nul")


def _write_hits(run, tools, ctx):
    """(tool, path, is_dir) for every write the covered tools performed."""
    hits = []
    for tool in tools:
        for ev in run.events_for(tool):
            if ev["event"] == "open" and ev.get("intent") == "write":
                path = ev.get("path")
                if isinstance(path, str) and not _is_null_device(path):
                    hits.append((tool, path, False))   # fd opens are internal
            elif ev["event"] in WRITE_EVENTS:
                args = ev.get("args") or []
                path = args[0] if args else ev["event"]
                if not _is_null_device(path):
                    hits.append((tool, path, ev["event"] in _DIR_EVENTS))
    return hits


def _ancestor_of_any(path, roots):
    if not path or not isinstance(path, str):
        return False
    p = os.path.normcase(os.path.abspath(path))
    for root in roots:
        if not root:
            continue
        r = os.path.normcase(os.path.abspath(root))
        if r == p or r.startswith(p + os.sep):
            return True
    return False


def _declared_arg_paths(run, tools, params, ctx):
    """Absolute paths the covered calls passed in their declared path args."""
    names = set(params.get("pathArgs", []))
    found = set()
    for tool, t0, t1, out in run.windows:
        if tool not in tools:
            continue
    # The plan holds the arguments; the run does not thread them here, so the
    # arg-path allowance is applied by prefix against the fixtures dir, which
    # is where every declared path argument in the plans points.
    found.add(os.path.normcase(os.path.abspath(plans_mod.FIXTURES)))
    return sorted(found)


def _expand(path, ctx):
    return path.replace("${APPDATA}", ctx["appdata"])


def _under_any(path, roots):
    if not path or not isinstance(path, str):
        return False
    p = os.path.normcase(os.path.abspath(path))
    for root in roots:
        if not root:
            continue
        r = os.path.normcase(os.path.abspath(root))
        if p == r or p.startswith(r + os.sep):
            return True
    return False


def _judge_error_as_value(declaration, run, tools, ctx):
    # Consumed by re-exercise with fuzz in a dedicated run; here we read the
    # fuzz outcomes the harness recorded on ctx.
    outcomes = ctx["fuzz_outcomes"]
    relevant = {t: outcomes[t] for t in tools if t in outcomes}
    if not relevant:
        return {"verdict": "not-covered",
                "evidence": "no fuzz outcomes for the covered tools"}
    bad = []
    total = 0
    for tool, outs in relevant.items():
        for out in outs:
            total += 1
            # error-as-value means the tool RETURNS an error, in a result
            # payload. An rpc-error is the framework converting a raised
            # exception; an isError result is the framework catching a raise
            # inside the tool. Both are the transport seeing the failure the
            # invariant says it never will. died/timeout are worse still.
            if out.kind != "result":
                bad.append("{}:{}".format(tool, out.kind))
            elif out.is_tool_error():
                bad.append("{}:raised(isError)".format(tool))
    if bad:
        return {"verdict": "fail",
                "evidence": "hostile input reached the transport as a "
                            "failure instead of an error value: "
                            + "; ".join(bad[:6])}
    return {"verdict": "pass",
            "evidence": "{} hostile inputs each returned an error value, no "
                        "raise, crash, or hang".format(total)}


def _strip_volatile(value, names):
    """A copy of value with every occurrence of the named fields removed.

    An invariant may declare fields volatile: values the tool allocates that
    carry no meaning to the caller (an opaque control id, a timestamp). They
    are excluded from the determinism comparison so a real difference in
    result content is not masked by incidental allocation, and incidental
    allocation is not mistaken for a real difference.
    """
    if not names:
        return value
    if isinstance(value, dict):
        return {k: _strip_volatile(v, names)
                for k, v in value.items() if k not in names}
    if isinstance(value, list):
        return [_strip_volatile(v, names) for v in value]
    return value


def _judge_determinism(inv, tools, ctx):
    replays = ctx["determinism"]
    volatile = (inv.get("params") or {}).get("volatile", [])
    covered = [t for t in tools if t in replays]
    if not covered:
        return {"verdict": "not-covered",
                "evidence": "no deterministic replay for the covered tools"}
    mismatches = []
    for tool in covered:
        runs = replays[tool]["runs"]
        stripped = [_canon(_strip_volatile(r, volatile)) for r in runs]
        if len(stripped) < 3 or len(set(stripped)) != 1 or runs[0] is None:
            mismatches.append(tool)
    if mismatches:
        return {"verdict": "fail",
                "evidence": "same input gave different output "
                            + ("(after excluding volatile {}) ".format(volatile)
                               if volatile else "")
                            + "across repeated and fresh calls: "
                            + ", ".join(mismatches)}
    note = " (excluding volatile {})".format(volatile) if volatile else ""
    return {"verdict": "pass",
            "evidence": "identical across two same-instance and one fresh "
                        "call{}: {}".format(note, ", ".join(covered))}


def _judge_property(inv, ctx):
    check_id = (inv.get("params") or {}).get("check")
    rows = ctx["property_results"].get(check_id)
    if rows is None:
        return {"verdict": "not-covered",
                "evidence": "no check registered for " + str(check_id)}
    failed = [r for r in rows if r["verdict"] != "pass"]
    if failed:
        return {"verdict": "fail",
                "evidence": "; ".join(r["evidence"] for r in failed[:4])}
    return {"verdict": "pass",
            "evidence": "; ".join(r["evidence"] for r in rows[:4])}


# ---------------------------------------------------------------------------
# Auxiliary runs: fuzz, determinism, property checks. Each launches its own
# instances so their observations do not bleed into the main window map.
# ---------------------------------------------------------------------------

def run_fuzz(name, plan, capture, server_python, monitor_log):
    if plan.get("skip_fuzz"):
        return {}
    schemas = {t["name"]: t["definition"].get("inputSchema", {})
               for t in capture["tools"]}
    outcomes = {}
    open(monitor_log, "w").close()
    session = Session(_cmd(plan, server_python), monitor_log=monitor_log)
    try:
        if session.initialize().kind != "result":
            return {}
        for tool in sorted(schemas):
            if tool == "scope":
                continue
            variants = plans_mod.fuzz_variants(schemas[tool], count=3)
            outs = [session.call(tool, v, plan.get("call_timeout", 60))
                    for v in variants]
            outcomes[tool] = outs
    finally:
        session.close()
    return outcomes


def run_determinism(name, plan, server_python, monitor_log):
    det_tools = [(t, a) for t, a, d in plan["exercise"] if d]
    # Within one instance, twice: catches a per-process counter, an RNG, or a
    # clock read -- the same call repeated must give the same answer. Then
    # across two fresh instances: catches state that resets per process but
    # varies by seed or environment. An invariant needs both to hold.
    same_a = _capture_payloads(plan, det_tools, server_python, monitor_log,
                               repeat=2)
    fresh_b = _capture_payloads(plan, det_tools, server_python, monitor_log,
                                repeat=1)
    result = {}
    for tool, _a in det_tools:
        runs = list(same_a.get(tool, []))          # two same-instance calls
        runs += list(fresh_b.get(tool, []))        # one fresh-instance call
        result[tool] = {"runs": runs}              # judged with volatile mask
    return result


def _capture_payloads(plan, det_tools, server_python, monitor_log, repeat=1):
    open(monitor_log, "w").close()
    env = {}
    if plan.get("appdata_sandbox"):
        env["APPDATA"] = tempfile.mkdtemp(prefix="saydo-det-")
    session = Session(_cmd(plan, server_python), env=env,
                      monitor_log=monitor_log)
    out = {}
    try:
        if session.initialize().kind != "result":
            return out
        for tool, args in det_tools:
            payloads = []
            for _ in range(repeat):
                res = session.call(tool, args, plan.get("call_timeout", 60))
                payloads.append(res.payload())
            out[tool] = payloads
    finally:
        session.close()
    return out


def run_properties(plan, server_python, monitor_log, ctx):
    results = {}
    checks = _declared_property_checks(ctx["declaration"])
    if not checks:
        return results
    open(monitor_log, "w").close()
    env = {}
    if plan.get("appdata_sandbox"):
        env["APPDATA"] = ctx["appdata"]
    session = Session(_cmd(plan, server_python), env=env,
                      monitor_log=monitor_log)
    try:
        if session.initialize().kind != "result":
            return results
        for check_id in checks:
            fn = plans_mod.PROPERTY_CHECKS.get(check_id)
            if fn:
                results[check_id] = fn(session, ctx)
    finally:
        session.close()
    return results


def _declared_property_checks(declaration):
    return [inv["params"]["check"] for inv in declaration["invariants"]
            if inv["type"] == "property" and (inv.get("params") or {}).get("check")]


def _launch(plan, server_python):
    """The argv that starts the server under test, for any plan shape:
    a full command argv, an installed module (-m), a script path, or a
    python -c launch string."""
    if plan.get("command_argv"):
        return list(plan["command_argv"])
    if plan.get("module"):
        return [server_python, "-m", plan["module"]]
    if plan.get("script"):
        return [server_python, plan["script"]]
    return [server_python, "-c", plan["launch"]]


#: The runner in force for the current run_conformance() call. The auxiliary
#: passes (fuzz, determinism, properties) launch their own instances, and they
#: must go through the same runner as the main pass -- otherwise a "contained"
#: verdict would rest partly on unconfined runs. Runs are sequential, so a
#: single module-level value is sufficient and is always cleared in a finally.
_ACTIVE_RUNNER = None


def _cmd(plan, server_python):
    base = _launch(plan, server_python)
    if _ACTIVE_RUNNER:
        return _ACTIVE_RUNNER.argv(plan, server_python, base)
    return base


def _canon(value):
    try:
        return json.dumps(value, sort_keys=True)
    except TypeError:
        return repr(value)


def _runtime_roots(server_python):
    roots = set()
    roots.add(os.path.dirname(os.path.abspath(server_python)))
    prefix = os.path.dirname(os.path.dirname(os.path.abspath(server_python)))
    roots.add(prefix)
    for p in sys.path:
        if p and os.path.isdir(p):
            roots.add(os.path.abspath(p))
    # site-packages of the server interpreter
    roots.add(os.path.join(prefix, "Lib"))
    roots.add(os.path.join(prefix, "lib"))
    return sorted(roots)


MONITOR_DESC = (
    "boundary egress proxy (any language) + cpython audit hook (python, "
    "in-runtime). Egress destinations are observed at the proxy; "
    "filesystem/subprocess via the audit hook. Not a sandbox: a raw socket to "
    "a bare IP ignoring proxy env, or a native syscall, is not compelled "
    "through either. Full enforcement needs a network-isolated container host.")


def _declared_hosts(declaration):
    """Every host the declaration says the tool may reach. Used as the proxy
    allowlist when the runner can actually enforce one."""
    hosts = set()
    for inv in declaration.get("invariants", []):
        if inv.get("type") == "network-allowlist":
            hosts.update((inv.get("params") or {}).get("hosts", []))
    return sorted(hosts)


def _safe_name(name):
    """A filename-safe form of a package name.

    Scoped npm packages contain a slash, so using the name directly in a path
    asks to write into a directory that does not exist. That failed as an
    exception attributed to the server rather than to the harness.
    """
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)[:80]


def run_conformance(name, plan, declaration, capture, server_python,
                    runner=None):
    """Exercise one server behind the boundary proxy and judge it. Returns a
    report dict. This is the in-process entry the CLI and the sweep both use."""
    global _ACTIVE_RUNNER
    plans_mod.write_fixtures()
    log = os.path.join(tempfile.gettempdir(), "saydo-monitor-{}.log".format(_safe_name(name)))
    egress_log = os.path.join(tempfile.gettempdir(),
                              "saydo-egress-{}.log".format(_safe_name(name)))

    if runner is None:
        import runner as runner_mod
        runner = runner_mod.make("local")
    ok, why = runner.available()
    if not ok:
        # Refuse rather than quietly falling back to a weaker runner: a run
        # that silently downgraded from containment to observation would make
        # the receipt's enforcement claim false.
        raise SystemExit("runner unavailable: " + why)

    # A canary is planted only when the declaration actually claims the tool
    # keeps its input to itself. Interception is intrusive, so it happens
    # because something was claimed, never by default.
    wants_content = any(inv.get("type") == "no-data-egress"
                        for inv in declaration.get("invariants", []))
    canaries = []
    if wants_content:
        import canary as canary_mod
        # TWO markers, one per run. Watching a single run can only show that
        # something left; changing the input between runs is what shows the
        # egress CARRIES the input rather than happening regardless of it.
        # The proxy watches for both and reports which one it saw.
        canaries = [canary_mod.new_marker(), canary_mod.new_marker()]
        os.environ["SAYDO_CANARY"] = canaries[0]

    proxy_address = runner.setup(egress_log,
                                 allow=_declared_hosts(declaration),
                                 canaries=canaries)
    os.environ.update(runner.env(proxy_address, None, egress_log))
    _ACTIVE_RUNNER = runner

    try:
        main_run = Run(name, plan, server_python, log, egress_log=egress_log,
                       runner=runner)
        appdata = main_run.appdata or tempfile.mkdtemp(prefix="saydo-prop-")
        ctx = {
            "declaration": declaration,
            "appdata": appdata,
            "enforcement": runner.enforcement,
            "runtime_roots": _runtime_roots(server_python),
            "fuzz_outcomes": run_fuzz(name, plan, capture, server_python, log),
            "determinism": run_determinism(name, plan, server_python, log),
        }
        ctx["property_results"] = run_properties(plan, server_python, log, ctx)

        if canaries:
            # The counterfactual. Run 1 already happened above with canary[0];
            # run 2 repeats the exercise with canary[1] so the two can be
            # compared. Nothing that only watches traffic can do this, because
            # it requires changing the input rather than observing it.
            import differential
            os.environ["SAYDO_CANARY"] = canaries[1]
            second = Run(name, plan, server_python, log,
                         egress_log=egress_log, runner=runner)
            # Each run is judged only on events it actually produced.
            def own(run):
                return [e for e in run.events
                        if e.get("t", 0) >= run.started - 0.5]

            ctx["differential"] = differential.classify([
                {"canary": canaries[0], "events": own(main_run)},
                {"canary": canaries[1], "events": own(second)},
            ])
    finally:
        _ACTIVE_RUNNER = None
        runner.teardown()

    verdicts, findings = judge(declaration, capture, main_run, ctx)
    tally = {}
    for v in verdicts:
        tally[v["verdict"]] = tally.get(v["verdict"], 0) + 1
    conformant = (not findings and tally.get("fail", 0) == 0
                  and tally.get("pass", 0) > 0)
    return {
        "subject": declaration["subject"],
        "declaration_serial": declaration["serialNumber"],
        "harness_version": "0.1.0",
        # The enforcement level is a property of how this run actually
        # happened, carried from the runner so no downstream artifact can
        # claim containment for a run that was merely observed.
        "enforcement": runner.enforcement,
        "monitor": runner.describe(),
        "conformant": conformant,
        "tally": tally,
        # Which destinations carry the tool's input and which do not. Empty
        # unless the declaration claimed no-data-egress, since establishing it
        # requires intervening on the input rather than observing traffic.
        "dataFlow": ctx.get("differential") or {},
        "verdicts": verdicts,
        "findings": findings,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("declaration")
    ap.add_argument("capture")
    ap.add_argument("report")
    ap.add_argument("--python", required=True,
                    help="interpreter that runs the server under test")
    ap.add_argument("--plan", help="plan name (default: server name)")
    ap.add_argument("--runner", default="local", choices=["local", "container"],
                    help="where the server runs. 'local' observes; 'container' "
                         "enforces (needs Docker on a Linux host)")
    ap.add_argument("--image", help="container image for --runner container")
    ap.add_argument("--runtime", help="container runtime, e.g. runsc for gVisor")
    ap.add_argument("--routed", action="store_true",
                    help="give the sandbox a gateway so bare-IP attempts are "
                         "recorded in any language, contained by a host "
                         "firewall instead of by the absence of a route")
    args = ap.parse_args()

    plans_mod.write_fixtures()
    with open(args.declaration, encoding="utf-8") as fh:
        declaration = json.load(fh)
    with open(args.capture, encoding="utf-8") as fh:
        capture = json.load(fh)

    name = args.plan or declaration["subject"]["name"]
    if name.startswith("@generic:"):
        # An arbitrary server, named by the command that starts it. A generic
        # exercise is synthesised from its own tools/list, so SayDo can be
        # pointed at software nobody wrote a plan for -- which is the normal
        # case for anyone auditing a tool they did not publish.
        argv = json.loads(name[len("@generic:"):])
        plan = plans_mod.synth_plan(capture, argv)
        name = _safe_name(declaration["subject"]["name"])
        if args.runner == "container":
            plan["container_argv"] = list(argv)
    else:
        plan = plans_mod.PLANS[name]
    import runner as runner_mod
    if args.runner == "container":
        if not args.image:
            raise SystemExit("--runner container needs --image")
        the_runner = runner_mod.make("container", image=args.image,
                                     runtime=args.runtime, routed=args.routed)
    else:
        the_runner = runner_mod.make("local")

    report = run_conformance(name, plan, declaration, capture, args.python,
                             runner=the_runner)
    verdicts, findings = report["verdicts"], report["findings"]
    conformant, tally = report["conformant"], report["tally"]
    with open(args.report, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    print("{}: conformant={} {}".format(name, conformant, tally))
    for v in verdicts:
        mark = {"pass": "  ok  ", "fail": " FAIL ",
                "not-covered": " ---- "}[v["verdict"]]
        print("  [{}] {:<26} {}".format(mark, v["id"], v["evidence"]))
    for f in findings:
        print("  FINDING {}: {} ({})".format(f["kind"], f["tool"], f["detail"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
