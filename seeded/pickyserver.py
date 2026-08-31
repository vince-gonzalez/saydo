"""A fixture that will work, but only if you read its schema.

The other two fixtures test what the harness concludes. This one tests whether
the harness can get a server to ACT at all, which turned out to be the thing
actually limiting it: a sweep of 280 published servers produced 835 verdict
rows and every one of them was `not-covered`. Nothing failed, nothing passed,
because nothing ever ran. That was reported as a fact about MCP servers. It was
a fact about the arguments we send.

Every tool here is cooperative. None wants a credential, none needs a network,
none is trying to be difficult. They simply state their requirements in the
inputSchema the way real tools do -- an enum, a format, a pattern, a non-empty
array, a default worth honouring -- and decline politely when handed the string
"test", which is what the old synthesizer sent for any string it did not
recognise by name.

The constraints are declared with Literal and pydantic Field so they reach the
published inputSchema. Written as bare type hints they do not: the SDK derives
the schema from annotations, `unit: str` publishes `{"type": "string"}`, and a
fixture whose requirements live only in its docstring tests nothing. That
mistake was made here first, which is the second time in a day a test quietly
did not run and looked exactly like a test that passed.

The bar: a harness that reads schemas makes all five of these act. A harness
that guesses makes none of them act, and then reports a clean sweep of a server
that did nothing. The second outcome is indistinguishable from a well-behaved
server unless you go and look, which is the whole reason this file exists.
"""

from __future__ import annotations

import os
import tempfile
from typing import Annotated, Literal

from pydantic import Field

from mcp.server import MCPServer

server = MCPServer(
    name="pickyserver", version="0.0.0",
    instructions="A test fixture that acts only when given schema-valid "
                 "arguments. It wants nothing else.")

_REFUSED = "declined: the argument does not satisfy the declared schema"


@server.tool(description="Report scope. CALL THIS FIRST. Takes no arguments.")
def scope() -> dict:
    return {
        "answers": ["Whether the harness reads inputSchema."],
        "cannot_answer": ["Anything real."],
        "note": "Every tool here acts if, and only if, its schema is honoured.",
    }


@server.tool(description="Convert a value. `unit` must be one of the "
                         "enumerated units.")
def convert(
    value: float,
    unit: Literal["celsius", "fahrenheit", "kelvin"],
) -> dict:
    # enum. The schema names the three acceptable values; the old synthesizer
    # sent "test" and this returned a refusal, which the harness recorded as
    # the tool having done nothing.
    if unit not in ("celsius", "fahrenheit", "kelvin"):
        return {"error": _REFUSED, "expected": ["celsius", "fahrenheit",
                                                "kelvin"]}
    # Acting means touching something observable, so the harness has an event
    # to attribute. A temp file is the cheapest honest side effect.
    path = os.path.join(tempfile.gettempdir(), "pickyserver_convert.txt")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("{} {}\n".format(value, unit))
    return {"converted": True, "unit": unit, "wrote": path}


@server.tool(description="Schedule something. `when` must be an ISO 8601 "
                         "date-time.")
def schedule(
    when: Annotated[str, Field(json_schema_extra={"format": "date-time"})],
) -> dict:
    # format: date-time. "test" is not one.
    import datetime
    try:
        datetime.datetime.fromisoformat(when.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return {"error": _REFUSED, "expected": "an ISO 8601 date-time"}
    path = os.path.join(tempfile.gettempdir(), "pickyserver_schedule.txt")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(when + "\n")
    return {"scheduled": True, "wrote": path}


@server.tool(description="Look up a record by id. `record_id` must match "
                         "^rec-[0-9]{4}$.")
def lookup(
    record_id: Annotated[str, Field(pattern=r"^rec-[0-9]{4}$")],
) -> dict:
    # pattern. A regex in the schema is the tool telling you the shape.
    import re
    if not re.match(r"^rec-[0-9]{4}$", record_id or ""):
        return {"error": _REFUSED, "expected": "^rec-[0-9]{4}$"}
    path = os.path.join(tempfile.gettempdir(), "pickyserver_lookup.txt")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(record_id + "\n")
    return {"found": True, "wrote": path}


@server.tool(description="Summarise a batch. `items` must contain at least "
                         "one string.")
def summarise(
    items: Annotated[list, Field(min_length=1)],
) -> dict:
    # minItems. The old synthesizer sent [] for every array, so any tool that
    # needs something to work on refused, every time.
    if not isinstance(items, list) or not items:
        return {"error": _REFUSED, "expected": "a non-empty array of strings"}
    path = os.path.join(tempfile.gettempdir(), "pickyserver_summarise.txt")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(",".join(str(i) for i in items) + "\n")
    return {"summarised": len(items), "wrote": path}


def main() -> None:
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
