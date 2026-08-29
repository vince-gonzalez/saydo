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
    return None


NET_EVENTS = {"socket.connect", "socket.getaddrinfo", "socket.bind",
              "socket.sendto"}
PROC_EVENTS = {"subprocess.Popen", "os.system", "os.exec", "os.spawn",
               "os.posix_spawn"}
WRITE_EVENTS = {"os.remove", "os.rename", "os.mkdir", "os.rmdir",
                "os.truncate", "os.link", "os.symlink", "shutil.rmtree",
                "shutil.copyfile", "shutil.move"}


class Run:
    """One launch of the server, its call windows, and its monitor events."""

    def __init__(self, name, plan, server_python, monitor_log):
        self.name = name
        self.windows = []   # (tool, t0, t1, outcome)
        self.events = []
        self._launch(plan, server_python, monitor_log)

    def _command(self, plan, server_python):
        return _launch(plan, server_python)

    def _launch(self, plan, server_python, monitor_log):
        open(monitor_log, "w").close()
        env = {}
        appdata = None
        if plan.get("appdata_sandbox"):
            appdata = tempfile.mkdtemp(prefix="warrant-appdata-")
            env["APPDATA"] = appdata
        self.appdata = appdata
        timeout = plan.get("call_timeout", 60)

        session = Session(self._command(plan, server_python), env=env,
                          monitor_log=monitor_log)
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
            time.sleep(0.05)
            self.events = _read_events(monitor_log)

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
                    if host:
                        observed.add(host)
                    if vtype == "no-network":
                        # Any network activity at all refutes the claim.
                        hits.append((tool, host or ev["event"]))
                    elif ev["event"] == "socket.getaddrinfo":
                        # Allowlist is about the NAME the code asked to
                        # resolve. connect/sendto carry only the resolved IP
                        # and are downstream of an allowed resolve, so they
                        # are not judged here.
                        if host and host not in allowed and not _loopback(host):
                            hits.append((tool, host))
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
    return host in ("127.0.0.1", "::1", "localhost")


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
        env["APPDATA"] = tempfile.mkdtemp(prefix="warrant-det-")
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
    an installed module (-m), a script path, or a python -c launch string."""
    if plan.get("module"):
        return [server_python, "-m", plan["module"]]
    if plan.get("script"):
        return [server_python, plan["script"]]
    return [server_python, "-c", plan["launch"]]


def _cmd(plan, server_python):
    return _launch(plan, server_python)


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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("declaration")
    ap.add_argument("capture")
    ap.add_argument("report")
    ap.add_argument("--python", required=True,
                    help="interpreter that runs the server under test")
    ap.add_argument("--plan", help="plan name (default: server name)")
    args = ap.parse_args()

    plans_mod.write_fixtures()
    with open(args.declaration, encoding="utf-8") as fh:
        declaration = json.load(fh)
    with open(args.capture, encoding="utf-8") as fh:
        capture = json.load(fh)

    name = args.plan or declaration["subject"]["name"]
    plan = plans_mod.PLANS[name]
    log = os.path.join(tempfile.gettempdir(),
                       "warrant-monitor-{}.log".format(name))

    main_run = Run(name, plan, args.python, log)

    appdata = main_run.appdata or tempfile.mkdtemp(prefix="warrant-prop-")
    ctx = {
        "declaration": declaration,
        "appdata": appdata,
        "runtime_roots": _runtime_roots(args.python),
        "fuzz_outcomes": run_fuzz(name, plan, capture, args.python, log),
        "determinism": run_determinism(name, plan, args.python, log),
    }
    ctx["property_results"] = run_properties(plan, args.python, log, ctx)

    verdicts, findings = judge(declaration, capture, main_run, ctx)

    tally = {}
    for v in verdicts:
        tally[v["verdict"]] = tally.get(v["verdict"], 0) + 1
    conformant = (not findings
                  and tally.get("fail", 0) == 0
                  and tally.get("pass", 0) > 0)

    report = {
        "subject": declaration["subject"],
        "declaration_serial": declaration["serialNumber"],
        "harness_version": "0.1.0",
        "monitor": "cpython-audit-hook; observes the Python runtime, not the "
                   "kernel; not a sandbox",
        "conformant": conformant,
        "tally": tally,
        "verdicts": verdicts,
        "findings": findings,
    }
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
