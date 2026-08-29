"""A minimal MCP stdio client for exercising a server under observation.

Deliberately not the SDK: the harness needs to see the transport exactly as
it is -- a JSON-RPC error, a dead process, a malformed line are all
observations, and a client library that smooths them over would be smoothing
over the evidence.

Every call returns a CallOutcome that says which of four things happened:

    result     the server returned a tools/call result
    rpc-error  the server returned a JSON-RPC error object
    died       the process exited before answering
    timeout    no answer within the deadline (process still running)

The caller decides what each of those means against the declaration; this
module only reports what occurred, with timestamps taken around the wire
exchange so monitor events can be attributed to the call.
"""

from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
import time


class CallOutcome:
    def __init__(self, kind, value=None, t0=0.0, t1=0.0, exit_code=None):
        self.kind = kind            # result | rpc-error | died | timeout
        self.value = value          # result dict or error dict
        self.t0, self.t1 = t0, t1   # wall-clock window of the exchange
        self.exit_code = exit_code

    def is_tool_error(self):
        """True when the result carries isError -- the framework caught a
        raise inside the tool and reported it as a tool execution error.
        That is distinct from the tool returning its own {"error": ...}
        payload, which leaves isError unset."""
        return bool(isinstance(self.value, dict) and self.value.get("isError"))

    def payload(self):
        """The tool's returned data, parsed, or None.

        Prefers structuredContent; falls back to the first text content block
        parsed as JSON, then to the raw text.
        """
        if self.kind != "result" or not isinstance(self.value, dict):
            return None
        if "structuredContent" in self.value:
            return self.value["structuredContent"]
        for block in self.value.get("content", []):
            if block.get("type") == "text":
                try:
                    return json.loads(block["text"])
                except (ValueError, KeyError):
                    return block.get("text")
        return self.value


class Session:
    """One launched server process and one initialized MCP session."""

    def __init__(self, command, env=None, monitor_log=None):
        full_env = dict(os.environ)
        if env:
            full_env.update(env)
        if monitor_log:
            full_env["SAYDO_MONITOR_LOG"] = monitor_log
            boot = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "monitor_boot")
            prior = full_env.get("PYTHONPATH")
            full_env["PYTHONPATH"] = boot + (os.pathsep + prior if prior else "")
        # Bytecode writing during import would appear as filesystem writes by
        # the tool. It is interpreter housekeeping, not tool behavior, so it
        # is turned off rather than filtered out afterwards.
        full_env["PYTHONDONTWRITEBYTECODE"] = "1"

        self.proc = subprocess.Popen(command, stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE,
                                     env=full_env)
        self._lines = queue.Queue()
        # Monitor events arrive on stderr when the server has no writable
        # log path -- which is the case inside a container. stderr must be
        # drained continuously regardless, or a chatty server fills the pipe
        # buffer and deadlocks.
        self.monitor_events = []
        self._errthread = threading.Thread(target=self._pump_stderr,
                                           daemon=True)
        self._errthread.start()
        self._reader = threading.Thread(target=self._pump, daemon=True)
        self._reader.start()
        self._next_id = 0
        self.started_at = time.time()

    def _pump(self):
        for line in self.proc.stdout:
            self._lines.put(line)
        self._lines.put(None)

    def _pump_stderr(self):
        """Drain stderr, keeping the monitor events and discarding the rest.

        The tool's own diagnostics are not evidence, so only lines carrying
        the monitor prefix are retained.
        """
        prefix = b"@@SAYDO@@ "
        try:
            for line in self.proc.stderr:
                if line.startswith(prefix):
                    try:
                        self.monitor_events.append(
                            json.loads(line[len(prefix):].decode("utf-8",
                                                                "replace")))
                    except ValueError:
                        pass
        except Exception:
            pass

    def _send(self, message):
        self.proc.stdin.write((json.dumps(message) + "\n").encode("utf-8"))
        self.proc.stdin.flush()

    def _await(self, want_id, timeout):
        deadline = time.time() + timeout
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                return "timeout", None
            try:
                line = self._lines.get(timeout=remaining)
            except queue.Empty:
                return "timeout", None
            if line is None:
                return "died", None
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                continue        # notifications or noise; not this answer
            if msg.get("id") != want_id:
                continue
            if "error" in msg:
                return "rpc-error", msg["error"]
            return "result", msg.get("result")

    def request(self, method, params, timeout=60):
        self._next_id += 1
        rid = self._next_id
        t0 = time.time()
        try:
            self._send({"jsonrpc": "2.0", "id": rid, "method": method,
                        "params": params})
        except OSError:
            return CallOutcome("died", t0=t0, t1=time.time(),
                               exit_code=self.proc.poll())
        kind, value = self._await(rid, timeout)
        t1 = time.time()
        if kind == "died":
            return CallOutcome("died", t0=t0, t1=t1,
                               exit_code=self.proc.poll())
        return CallOutcome(kind, value, t0=t0, t1=t1)

    def initialize(self, timeout=60):
        out = self.request("initialize", {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "saydo-harness", "version": "0.1.0"},
        }, timeout)
        if out.kind == "result":
            try:
                self._send({"jsonrpc": "2.0",
                            "method": "notifications/initialized"})
            except OSError:
                pass
        return out

    def list_tools(self, timeout=60):
        return self.request("tools/list", {}, timeout)

    def call(self, name, arguments, timeout=60):
        return self.request("tools/call",
                            {"name": name, "arguments": arguments}, timeout)

    def alive(self):
        return self.proc.poll() is None

    def close(self):
        try:
            self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.ended_at = time.time()
