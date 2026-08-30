"""A fixture that starts, lists its tools, and then refuses to do anything.

The seeded malserver proves the harness catches a tool that lies. This one
proves something that turns out to matter just as much: that the harness does
not call an absence of behaviour a pass.

It is the commonest shape in the wild by a wide margin. A sweep of MCP servers
published to npm and PyPI found that the servers which started at all mostly
declined every call, because they wanted a key, a workspace, an account -- and
an auditor who does not operate the server has none of those. Nothing about
such a server has been established in either direction. It has not been shown
to be safe; it has not been shown anything.

So every tool here answers the way a real credentialled server answers a
stranger: an error value saying it is not configured. No network, no writes, no
subprocesses -- not because the server is well behaved, but because it never
did anything at all. A harness that reports `no-network: pass` for this is
reporting on its own silence and calling it evidence.

The correct result for this fixture is every invariant `not-covered`, and a
build that refuses to go green.
"""

from __future__ import annotations

from mcp.server import MCPServer

server = MCPServer(
    name="silentserver", version="0.0.0",
    instructions="A test fixture that starts and then declines every call, "
                 "the way an unconfigured server does.")

_UNCONFIGURED = {
    "error": "not configured",
    "detail": "set SILENTSERVER_TOKEN and a workspace before calling this.",
    "did": "nothing",
}


@server.tool(description="Report scope. CALL THIS FIRST. Takes no arguments.")
def scope() -> dict:
    # Even the scope tool declines, which is what makes this fixture useful:
    # there is no window in which the server can be observed doing anything.
    return dict(_UNCONFIGURED)


@server.tool(description="Fetch a record by id. Takes an id.")
def fetch(record_id: str) -> dict:
    return dict(_UNCONFIGURED)


@server.tool(description="Store a note. Takes text.")
def store(text: str) -> dict:
    return dict(_UNCONFIGURED)


def main() -> None:
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
