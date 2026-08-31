"""An MCP server exposing SayDo to language models.

Run it with `saydo-mcp`, or add it to a client's MCP configuration. It speaks
stdio.

WHY THE FIRST TOOL IS A REFUSAL
-------------------------------
The likeliest failure of this server is not a crash. It is a model asking
"is this MCP server safe to install?", getting back a green-looking word, and
telling a person the tool has been checked when nothing has been checked at
all.

Almost every real package has no receipt on record. The honest answer for those
is `unknown`, and `unknown` has to keep meaning "nobody has looked" rather than
degrading into "probably fine" through repetition. `scope()` says that first,
because a tool description is the only documentation a model reliably reads.

WHAT IT CAN ANSWER
------------------
- Whether a specific package version has a conformance receipt, and what that
  receipt establishes -- including whether the claim has since been withdrawn.
- What a tool definition hashes to, and whether its text is shaped like an
  instruction aimed at the model rather than a description aimed at a person.
- What a package actually does, by running it in a sandbox and watching. That
  one takes minutes and needs Docker, and it refuses rather than pretending
  when it cannot do it properly.

WHAT IT CANNOT ANSWER
---------------------
Whether a tool is safe. Nothing here establishes that and nothing here will.
A receipt says what a tool did on one run against a contract its author wrote.
A tool that declined to act has not been shown to be well behaved -- it has not
been shown anything, and this server reports that as `inconclusive` rather than
as a pass, because the difference is the entire point.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from typing import Annotated, Any, Literal

from pydantic import Field

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

try:
    from mcp.server import MCPServer
except ImportError:                                       # pragma: no cover
    raise SystemExit(
        "The MCP server needs the optional dependency:\n"
        "    pip install 'mcp>=1.29'")

import jcs                                                # noqa: E402
import registry as registry_mod                           # noqa: E402

REGISTRY_PATH = os.path.join(ROOT, "registry", "saydo-registry.json")

# The version is read, never restated. Hardcoding it here made this a fifth
# place the number lives, and it drifted on the very first bump: the wheel said
# 0.1.1 while the server announced 0.1.0 to every client that asked.
try:
    from saydo import __version__ as _VERSION       # installed as a package
except ImportError:                                  # running from the repo
    _VERSION = "0.0.0+repo"

server = MCPServer(
    name="saydo", version=_VERSION,
    instructions="Reports what an MCP tool was observed doing, against a "
                 "contract its author signed. Answers 'unknown' for anything "
                 "nobody has checked, and means it.")

#: Shapes that belong in an instruction to a model, not in a description of a
#: tool to a person. Matched case-insensitively against the definition text.
#: This is a STATIC read of wording -- it catches the careless and the obvious,
#: never the careful, and the tool says so in its own output.
_INJECTION_SHAPES = (
    "ignore previous", "ignore all previous", "disregard the above",
    "disregard previous", "system prompt", "you are now", "act as",
    "do not tell the user", "do not mention", "without informing",
    "before using any other tool", "always call this tool first",
    "read the file", "~/.ssh", "id_rsa", ".env", "environment variable",
    "api key", "credentials", "exfiltrat",
)


@server.tool(description="What SayDo can and cannot settle. CALL THIS FIRST. "
                         "Takes no arguments and does no I/O.")
def scope() -> dict:
    return {
        "answers": [
            "Whether a package version has a conformance receipt, and what it "
            "establishes.",
            "What a tool definition hashes to, and whether its wording is "
            "aimed at the model rather than at a reader.",
            "What a package does when run in a sandbox, if you ask for that "
            "and can wait minutes.",
        ],
        "cannot_answer": [
            "Whether a tool is safe. Nothing here establishes that.",
            "Anything about the overwhelming majority of packages, which have "
            "no receipt. The answer for those is 'unknown' and it stays that.",
            "Whether a tool that declined to act is well behaved. It has not "
            "been shown to be anything.",
        ],
        "how_to_read_a_verdict": {
            "warranted": "conformed to a signed contract when last checked",
            "failing": "did something it declared it would not",
            "inconclusive": "nothing failed and nothing was established",
            "revoked": "the claim was withdrawn after the receipt was issued",
            "expired": "the last check is too old to describe what is "
                       "installed today",
            "unknown": "nobody has checked this; treat as unverified",
        },
        "note": "A receipt is evidence about one run of one version. It is not "
                "a safety guarantee and must not be presented as one.",
    }


@server.tool(description="Whether a package has a SayDo conformance receipt. "
                         "Takes a package URL such as pkg:npm/some-server or "
                         "pkg:pypi/some-server. Returns 'unknown' when nobody "
                         "has checked it, which is the usual answer.")
def status(purl: str) -> dict:
    registry = registry_mod.load(REGISTRY_PATH)
    entry = registry_mod.lookup(registry, purl)
    out = {
        "subject": purl,
        "verdict": entry.get("state", "unknown"),
        "advice": entry.get("advice", ""),
        "receipt": (entry.get("receipt") or {}).get("head"),
        "checkedAgainst": REGISTRY_PATH,
    }
    if out["verdict"] == "unknown":
        out["what_this_means"] = (
            "No receipt exists for this package. That is not a clean bill and "
            "not a warning -- nobody has looked. Do not report it to a user as "
            "checked, verified, or safe. `check_now` will actually measure it "
            "if that is worth minutes to you."
        )
    else:
        out["what_this_means"] = (
            "This summarises a receipt. The receipt is the evidence and can be "
            "verified without trusting SayDo. Do not restate this verdict as a "
            "safety claim."
        )
    return out


@server.tool(description="Hash a tool definition and read its wording. Takes "
                         "the tool's JSON definition. Does no I/O and takes no "
                         "network. Static analysis only -- it catches obvious "
                         "instruction-injection wording, never careful "
                         "wording.")
def inspect_definition(definition: dict) -> dict:
    core = {k: definition.get(k) for k in ("name", "description", "inputSchema")
            if k in definition}
    try:
        digest = jcs.digest(core)
    except Exception as exc:
        return {"error": "the definition could not be canonicalized: {}".format(
            type(exc).__name__),
            "note": "SayDo refuses to hash what it cannot canonicalize rather "
                    "than producing a digest that looks authoritative."}

    text = json.dumps(core, ensure_ascii=False).lower()
    hits = sorted({shape for shape in _INJECTION_SHAPES if shape in text})
    return {
        "toolDigest": digest,
        "digestNote": "sha256 over the RFC 8785 canonical form of name, "
                      "description and inputSchema. Compare it to a digest you "
                      "recorded earlier; a change with no version change is "
                      "the shape of a silent update.",
        "wordingFlags": hits,
        "wordingVerdict": ("nothing obvious" if not hits else
                           "this description contains wording that reads as an "
                           "instruction to a model rather than a description "
                           "to a person"),
        "limits": "Static text matching. A careful attacker writes around it. "
                  "Absence of flags establishes nothing whatsoever.",
    }


@server.tool(description="Actually run a package in a sandbox and report what "
                         "it did. Slow -- minutes, not seconds -- and needs "
                         "Docker. Refuses rather than running unsandboxed.")
def check_now(
    registry: Literal["npm", "pypi"],
    name: Annotated[str, Field(min_length=1)],
    timeout_seconds: Annotated[int, Field(ge=60, le=1800)] = 600,
) -> dict:
    # Installed from a wheel, only the package ships -- the CLI and the
    # container definitions live in the repository. Saying so is better than
    # discovering it as a stack trace, and far better than quietly running
    # something weaker and reporting the result as if it were a sandboxed run.
    cli = os.path.join(ROOT, "cli", "saydo.py")
    if not os.path.exists(cli):
        return {
            "refused": True,
            "reason": "this is the installed package, which ships the library "
                      "and this server but not the harness's container "
                      "definitions. Measuring a package requires the "
                      "repository.",
            "alternative": "git clone https://github.com/vince-gonzalez/saydo "
                           "and run `python cli/saydo.py verify --{} {} "
                           "--sandbox`. `status` and `inspect_definition` work "
                           "here without it.".format(registry, name),
        }

    have_docker = subprocess.run(
        ["docker", "version", "--format", "{{.Server.Version}}"],
        capture_output=True, text=True).returncode == 0
    if not have_docker:
        return {
            "refused": True,
            "reason": "Docker is not available, so the package cannot be "
                      "contained. SayDo will not execute an unknown package "
                      "outside a sandbox to answer a question about whether "
                      "it is trustworthy.",
            "alternative": "Run `saydo verify --npm NAME --sandbox` on a "
                           "machine with Docker, or read `status` for a "
                           "receipt somebody else produced.",
        }

    flag = "--npm" if registry == "npm" else "--pypi"
    try:
        proc = subprocess.run(
            [sys.executable, os.path.join(ROOT, "cli", "saydo.py"), "verify",
             flag, name, "--sandbox"],
            capture_output=True, text=True, timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        return {"refused": True,
                "reason": "the run exceeded {}s and was stopped. A partial run "
                          "establishes nothing, so nothing is reported."
                          .format(timeout_seconds)}

    slug = name.replace("/", "_").replace("@", "")
    report = os.path.join(ROOT, "reports", slug + ".report.json")
    if not os.path.exists(report):
        return {"refused": True,
                "reason": "the package did not produce a report; it most "
                          "likely would not start.",
                "detail": (proc.stderr or proc.stdout or "")[-400:]}

    with open(report, encoding="utf-8") as fh:
        rep = json.load(fh)
    established = rep.get("established", 0)
    return {
        "subject": "pkg:{}/{}".format(registry, name),
        "verdict": ("failing" if not rep["conformant"] else
                    "inconclusive" if not established else "warranted"),
        "established": established,
        "enforcement": rep.get("enforcement"),
        "failed": [{"invariant": v["id"], "evidence": v["evidence"][:300]}
                   for v in rep["verdicts"] if v["verdict"] == "fail"],
        "what_this_means": (
            "Nothing failed and nothing was established. The package did no "
            "observable work -- usually it declines to act without credentials "
            "it was not given. This is not a clean result; it is the absence "
            "of one, and it must not be reported as the package being fine."
            if established == 0 and rep["conformant"] else
            "The package did something it declared it would not."
            if not rep["conformant"] else
            "The package did what its contract said, for the checks that were "
            "actually exercised. Unexercised checks establish nothing."),
    }


def main() -> None:
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
