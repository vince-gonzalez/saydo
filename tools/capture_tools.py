"""Capture the live tool definitions of an MCP stdio server, with digests.

Launches the server command, performs the MCP initialize handshake over
stdio, requests tools/list, and writes one JSON document per server:

    {
      "server": {"name": ..., "version": ..., "instructions": ...},
      "protocolVersion": ...,
      "tools": [
        {"name": ..., "definition": {name, description, inputSchema},
         "definitionDigest": {algorithm, value, canonicalization, covers}}
      ]
    }

The definition digest is computed exactly as TBOM v1.0.2 computes it: sha256
over the RFC 8785 canonical form of the covered fields. A declaration binds
to these digests; a conformance run recomputes them and stops on mismatch.

The capture is taken from the RELEASED artifact (whatever is installed in the
Python environment this runs under), not from a working tree. A working tree
can drift from what was published; a stranger installs the release.

Usage:
    python capture_tools.py <output.json> -- <command> [args...]
"""

from __future__ import annotations

import json
import subprocess
import sys

import jcs

PROTOCOL = "2025-06-18"


def _rpc(id_, method, params):
    msg = {"jsonrpc": "2.0", "id": id_, "method": method}
    if params is not None:
        msg["params"] = params
    return (json.dumps(msg) + "\n").encode("utf-8")


def _notify(method):
    return (json.dumps({"jsonrpc": "2.0", "method": method}) + "\n").encode("utf-8")


def _read_response(stream, want_id, proc=None):
    """Next response with the given id; notifications in between are skipped."""
    while True:
        line = stream.readline()
        if not line:
            # A server that dies on startup closes stdout, and reporting only
            # that says nothing about WHY. The reason is on its stderr -- an
            # ImportError, a missing environment variable, a stack trace -- and
            # without it a CI failure is a mystery that has to be reproduced
            # locally to diagnose. It is quoted here instead.
            detail = ""
            if proc is not None:
                try:
                    proc.stdin.close()
                except Exception:
                    pass
                try:
                    err = (proc.stderr.read() or b"").decode("utf-8", "replace")
                except Exception:
                    err = ""
                err = err.strip()
                if err:
                    detail = "; the server said:\n" + err[-1500:]
                elif proc.poll() is not None:
                    detail = ("; it exited {} and said nothing"
                              .format(proc.returncode))
            raise RuntimeError("server closed stdout before answering id {}{}"
                               .format(want_id, detail))
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            # Servers print banners, version notices and deprecation warnings
            # to stdout alongside the protocol. Treating that as fatal made
            # perfectly working servers look unstartable, which is a failure
            # of the harness reported as a finding about the tool.
            continue
        if msg.get("id") == want_id:
            if "error" in msg:
                raise RuntimeError("server error: {}".format(msg["error"]))
            return msg["result"]


def capture(command):
    proc = subprocess.Popen(command, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        proc.stdin.write(_rpc(1, "initialize", {
            "protocolVersion": PROTOCOL,
            "capabilities": {},
            "clientInfo": {"name": "saydo-capture", "version": "0.1.0"},
        }))
        proc.stdin.flush()
        init = _read_response(proc.stdout, 1, proc)

        proc.stdin.write(_notify("notifications/initialized"))
        proc.stdin.flush()

        proc.stdin.write(_rpc(2, "tools/list", {}))
        proc.stdin.flush()
        listed = _read_response(proc.stdout, 2, proc)
    finally:
        proc.stdin.close()
        proc.terminate()
        proc.wait(timeout=10)

    tools = []
    for tool in listed["tools"]:
        covered = {"name": tool["name"],
                   "description": tool.get("description", ""),
                   "inputSchema": tool.get("inputSchema", {})}
        covers = "{name,description,inputSchema}"
        if "outputSchema" in tool:
            covered["outputSchema"] = tool["outputSchema"]
            covers = "{name,description,inputSchema,outputSchema}"
        tools.append({
            "name": tool["name"],
            "definition": covered,
            "definitionDigest": {
                "algorithm": "sha256",
                "value": jcs.digest(covered),
                "canonicalization": "rfc8785",
                "covers": covers,
            },
        })

    info = init.get("serverInfo", {})
    return {
        # `instructions` is the prose a server hands the client on connect --
        # its own description of itself, and the place its promises live. It
        # was being discarded, so a server could claim "local-only, no
        # telemetry" in the one field every client reads and nothing here ever
        # saw the sentence.
        "server": {"name": info.get("name", ""),
                   "version": info.get("version", ""),
                   "instructions": init.get("instructions", "")},
        "protocolVersion": init.get("protocolVersion", ""),
        "tools": tools,
    }


def main():
    argv = sys.argv[1:]
    if "--" not in argv or argv.index("--") != 1:
        raise SystemExit(__doc__)
    out_path = argv[0]
    command = argv[2:]
    result = capture(command)
    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(result, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    print("{}: {} tools, server {} {}".format(
        out_path, len(result["tools"]),
        result["server"]["name"], result["server"]["version"]))


if __name__ == "__main__":
    main()
