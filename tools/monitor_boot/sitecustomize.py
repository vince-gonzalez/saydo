"""Runtime observation for a tool under test. Injected, not linked.

The harness prepends this directory to PYTHONPATH before launching the
server, so the interpreter imports it during startup -- before the server's
own code runs -- and the audit hook sees everything after that: files opened,
sockets connected, hostnames resolved, processes spawned.

Two honesty notes, load-bearing:

  1. CPython audit hooks cannot be removed once installed, but they observe
     the PYTHON runtime, not the kernel. Code that calls the OS directly
     (ctypes, a native extension built to evade) walks past this. What this
     monitor supports is therefore: catching drift, accidents, and ordinary
     misbehavior, and refuting false declarations made by ordinary code. It
     is not a sandbox and no receipt should call it one.
  2. The hook must never raise -- an exception here propagates into whatever
     the server was doing and manufactures a failure the tool did not have.
     Every path is wrapped accordingly.

Events are appended as JSON lines to the file named by SayDo_MONITOR_LOG,
through a file descriptor opened before the hook exists, so the monitor's own
writing is not in the record it produces.
"""

import json
import os
import sys
import time

_WATCHED = {
    "open",
    "socket.connect",
    "socket.getaddrinfo",
    "socket.bind",
    "socket.sendto",
    "subprocess.Popen",
    "os.system",
    "os.exec",
    "os.spawn",
    "os.posix_spawn",
    "os.remove",
    "os.rename",
    "os.mkdir",
    "os.rmdir",
    "os.truncate",
    "os.link",
    "os.symlink",
    "shutil.rmtree",
    "shutil.copyfile",
    "shutil.move",
}

_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC


def _text(value, depth=0):
    """A short, JSON-safe rendering of an audit-event argument."""
    try:
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if isinstance(value, str):
            return value[:512]
        if isinstance(value, bytes):
            return value[:512].decode("utf-8", "replace")
        if isinstance(value, (list, tuple)) and depth < 2:
            return [_text(v, depth + 1) for v in value[:8]]
        return repr(value)[:256]
    except Exception:
        return "<unrenderable>"


#: Marks a monitor event on stderr. Inside a container there is no shared
#: filesystem to write a log to, and a bind mount would punch a hole in the
#: isolation being tested. stderr is a pipe the harness already owns, so
#: events ride out on it, prefixed so the tool's own stderr is never mistaken
#: for evidence.
STDERR_PREFIX = "@@SAYDO@@ "


def _install():
    path = os.environ.get("SAYDO_MONITOR_LOG")
    to_stderr = os.environ.get("SAYDO_MONITOR_STDERR") == "1"
    if not path and not to_stderr:
        return
    fd = -1
    if path:
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND)
        except OSError:
            if not to_stderr:
                return

    state = {"busy": False}

    def classify_open(args):
        """(path, intent) for an 'open' event, best effort."""
        target = _text(args[0]) if args else None
        mode = args[1] if len(args) > 1 else None
        flags = args[2] if len(args) > 2 else None
        intent = "read"
        try:
            if isinstance(mode, str) and any(c in mode for c in "wax+"):
                intent = "write"
            elif mode is None and isinstance(flags, int) \
                    and flags & _WRITE_FLAGS:
                intent = "write"
        except Exception:
            intent = "unknown"
        return target, intent

    def hook(event, args):
        if event not in _WATCHED or state["busy"]:
            return
        state["busy"] = True
        try:
            row = {"t": time.time(), "event": event}
            if event == "open":
                target, intent = classify_open(args)
                row["path"] = target
                row["intent"] = intent
            else:
                row["args"] = [_text(a) for a in args[:4]]
            text = json.dumps(row)
            if fd >= 0:
                os.write(fd, (text + "\n").encode("utf-8", "replace"))
            if to_stderr:
                os.write(2, (STDERR_PREFIX + text + "\n")
                         .encode("utf-8", "replace"))
        except Exception:
            pass
        finally:
            state["busy"] = False

    sys.addaudithook(hook)


_install()
