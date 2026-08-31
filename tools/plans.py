"""Exercise plans: how the harness drives each server, and the property checks.

A plan is evidence design, not test convenience. Each step exists to give
some declared invariant an observation window: a no-network claim needs the
tool to actually run under the monitor; a determinism claim needs the same
call made twice in two fresh processes; an egress allowlist needs a call
that genuinely goes out. Steps marked deterministic are replayed in a second
instance and compared.

The fuzz pool serves the error-as-value invariant only, so it contains
values that are SCHEMA-valid and semantically hostile: paths that do not
exist, expressions outside the language, traversal shapes, control
characters, oversized strings. Schema-invalid input is the SDK's to refuse;
these must reach the tool.

authorecon's networked steps use Josiah Carberry's ORCID
(0000-0002-1825-0097), ORCID's own fictional test author, so exercising the
tool queries nobody real.
"""

from __future__ import annotations

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(os.path.dirname(HERE), "fixtures")

TINY_MM = os.path.join(FIXTURES, "tiny.mm")
SAMPLE_DOC = os.path.join(FIXTURES, "sample-document.txt")
SOUNDS_DIR = os.path.join(FIXTURES, "sounds")
GITREPO = os.path.join(FIXTURES, "gitrepo")
MALSERVER = os.path.join(os.path.dirname(HERE), "seeded", "malserver.py")

CARBERRY = "0000-0002-1825-0097"
ONE_REFERENCE = ("Shannon, C. E. (1948). A mathematical theory of "
                 "communication. Bell System Technical Journal, 27(3), "
                 "379-423.")

# ---------------------------------------------------------------------------
# Fuzz pools, by JSON-schema type. Deterministic: no randomness, so a failing
# variant fails the same way on the next run.
# ---------------------------------------------------------------------------

FUZZ_BY_TYPE = {
    "string": [
        "",
        "@@garbage@@",
        "Z:\\no\\such\\path\\anywhere.mm",
        "..\\..\\..\\..\\windows\\win.ini",
        "\u0000nul\u0000",
        "A" * 4096,
    ],
    "integer": [-1, 0, 2 ** 40],
    "number": [-1, 0, 2 ** 40],
    "boolean": [True],
    "array": [[], ["@@garbage@@"]],
    "object": [{}, {"unexpected": ["@@garbage@@"]}],
}


def _hostile_for(schema, i):
    """One schema-valid hostile value for a property schema.

    Respects nested constraints so the value stays inside what the SDK would
    accept and reaches the tool: an array of objects yields objects, not
    strings, because a string item is schema-invalid and would be refused by
    the framework rather than tested against error-as-value.
    """
    kind = schema.get("type", "string")
    if isinstance(kind, list):
        kind = kind[0] if kind else "string"
    if kind == "array":
        items = schema.get("items", {})
        itype = items.get("type", "string")
        if itype == "object":
            return [[], [_hostile_object(items, i)]][i % 2]
        return [[], [_hostile_for(items, i)]][i % 2]
    if kind == "object":
        return _hostile_object(schema, i)
    pool = FUZZ_BY_TYPE.get(kind, FUZZ_BY_TYPE["string"])
    return pool[i % len(pool)]


def _hostile_object(schema, i):
    """A schema-valid object carrying hostile field values, plus a required
    fields filled. If the object is unconstrained, an empty object is the
    hostile case (missing everything the tool hopes for)."""
    props = schema.get("properties", {})
    if not props:
        return [{}, {"unexpected": "@@garbage@@"}][i % 2]
    obj = {}
    for name in schema.get("required", list(props)):
        obj[name] = _hostile_for(props.get(name, {}), i)
    return obj


def fuzz_variants(input_schema, count=3):
    """`count` argument sets for one tool, each schema-valid and hostile."""
    props = (input_schema or {}).get("properties", {})
    required = (input_schema or {}).get("required", list(props))
    variants = []
    for i in range(count):
        args = {name: _hostile_for(props.get(name, {}), i) for name in required}
        variants.append(args)
    return variants


# ---------------------------------------------------------------------------
# Property checks. Each returns a list of {"verdict", "evidence"} rows and is
# registered under the check id the declaration names. A property whose check
# id is not registered here is reported NOT COVERED by the harness -- never
# passed by omission.
# ---------------------------------------------------------------------------

def _payload(outcome):
    got = outcome.payload()
    return got if isinstance(got, dict) else {}


def check_undecided_on_overlap(session, ctx):
    rows = []
    cases = [
        # Overlapping, non-exact enclosures: the verdict must be UNDECIDED.
        ({"left": "pi", "comparison": "==", "right": "pi"}, "UNDECIDED"),
        ({"left": "sqrt2 * sqrt2", "comparison": "==", "right": "2"},
         "UNDECIDED"),
        # Control: separated enclosures must still decide. A checker that
        # calls everything UNDECIDED would pass the two cases above while
        # proving nothing.
        ({"left": "1", "comparison": "<", "right": "2"}, "TRUE"),
    ]
    for args, expected in cases:
        got = _payload(session.call("decide", args)).get("verdict")
        rows.append({
            "verdict": "pass" if got == expected else "fail",
            "evidence": "decide({left} {comparison} {right}) -> {got}, "
                        "expected {want}".format(got=got, want=expected,
                                                 **args),
        })
    return rows


def check_decimal_literal_exact(session, ctx):
    args = {"left": "0.1 + 0.2", "comparison": "==", "right": "0.3"}
    got = _payload(session.call("decide", args)).get("verdict")
    return [{
        "verdict": "pass" if got == "TRUE" else "fail",
        "evidence": "decide(0.1 + 0.2 == 0.3) -> {}, expected TRUE "
                    "(the decimal literal, not the nearest double)".format(got),
    }]


def check_refuse_invalid_write(session, ctx):
    """A layout that fails validation is never written."""
    profiles = os.path.join(ctx["appdata"], "RemapWrap", "profiles")
    before = set(os.listdir(profiles)) if os.path.isdir(profiles) else set()
    broken = {
        "schema": 1,
        "name": "HarnessBroken",
        "pages": [{"name": "Page 1", "cols": 4, "rows": 4,
                   "keys": [{"type": "key", "label": "Dead key"}]}],
    }
    payload = _payload(session.call("save_board",
                                    {"profile": broken, "name": "HarnessBroken"}))
    after = set(os.listdir(profiles)) if os.path.isdir(profiles) else set()
    wrote = sorted(after - before)
    refused = payload.get("written") is False
    return [{
        "verdict": "pass" if refused and not wrote else "fail",
        "evidence": "save_board(broken layout) -> written={}, new files={}"
                    .format(payload.get("written"), wrote or "none"),
    }]


PROPERTY_CHECKS = {
    "certivl.undecided-on-overlap": check_undecided_on_overlap,
    "certivl.decimal-literal-exact": check_decimal_literal_exact,
    "remapwrap.refuse-invalid-write": check_refuse_invalid_write,
}


# ---------------------------------------------------------------------------
# Plans. launch: -c line run by the harness's Python. exercise: (tool, args,
# deterministic) -- deterministic steps are replayed in a second fresh
# instance and compared. chain: steps whose argument is built from a prior
# step's payload.
# ---------------------------------------------------------------------------

PLANS = {
    "certivl": {
        "launch": "from certivl.mcp_server import main; main()",
        "exercise": [
            ("scope", {}, True),
            ("decide", {"left": "1", "comparison": "<", "right": "2"}, True),
            ("decide", {"left": "pi", "comparison": ">", "right": "3.15"}, True),
            ("enclose", {"expression": "sqrt2 * sqrt2"}, True),
        ],
    },
    "loadbearing": {
        "launch": "from loadbearing.mcp_server import main; main()",
        "exercise": [
            ("scope", {}, True),
            ("measure_severing",
             {"database_path": TINY_MM, "targets": ["ax-1"]}, True),
            ("measure_with_witness",
             {"database_path": TINY_MM, "targets": ["ax-1"]}, False),
        ],
    },
    "mmforge": {
        "launch": "from mmforge.mcp_server import main; main()",
        "exercise": [
            ("scope", {}, True),
            ("analyse_necessity",
             {"database_path": TINY_MM, "axioms": ["ax-1"]}, True),
            ("census_guards", {"database_path": TINY_MM}, True),
        ],
    },
    "authorecon": {
        "launch": "from authorecon.mcp_server import main; main()",
        "call_timeout": 180,
        "exercise": [
            ("scope", {}, True),
            ("scan_document", {"path": SAMPLE_DOC}, False),
            ("check_venues", {"orcid": CARBERRY}, False),
            ("check_references", {"bibliography": ONE_REFERENCE}, False),
        ],
        # error-as-value is not declared for this server; fuzzing it would
        # generate observations no invariant consumes, at live APIs' expense.
        "skip_fuzz": True,
    },
    "remapwrap": {
        "launch": "from remapwrap.mcp_server import main; main()",
        "appdata_sandbox": True,
        "exercise": [
            ("scope", {}, True),
            ("check_layout",
             {"layout": {"cols": 4, "rows": 4, "keys": []}}, True),
            ("build_board",
             {"entries": [{"label": "Yes", "command": "speak.text",
                           "arg": "Yes"}],
              "name": "HarnessBoard"}, True),
            ("build_mixer", {"applications": ["Discord"]}, True),
            ("build_soundboard", {"folder": SOUNDS_DIR}, True),
        ],
        "chain": [
            # A valid save exercises write-scope with a real, permitted write.
            {"from": "build_board", "take": "profile",
             "tool": "save_board", "arg": "profile",
             "extra": {"name": "HarnessBoard"}},
        ],
    },
    # --- third-party servers (NOT written by F-Keys) -------------------------
    # The generalization test: real Python MCP servers off PyPI, launched as
    # installed modules, driven by real arguments. mcp-server-time is pure
    # computation (should conform to a no-network/no-write envelope);
    # mcp-server-fetch reaches the internet by design (a no-network claim on
    # it must be caught).
    "mcp-server-time": {
        "module": "mcp_server_time",
        "exercise": [
            # get_current_time reads the wall clock, so it is deliberately not
            # marked deterministic. convert_time is pure and is.
            ("get_current_time", {"timezone": "America/New_York"}, False),
            ("convert_time", {"source_timezone": "America/New_York",
                              "time": "14:30",
                              "target_timezone": "Europe/London"}, True),
        ],
    },
    "mcp-server-fetch": {
        "module": "mcp_server_fetch",
        "call_timeout": 60,
        "exercise": [
            ("fetch", {"url": "https://example.com/", "max_length": 500}, False),
        ],
        "skip_fuzz": True,   # fuzzed URLs would be live requests to junk hosts
    },
    # A Node MCP server (Phase-1 fixture). The Python audit hook cannot see it
    # at all; only the boundary egress proxy can. Its 'grab' tool fetches a
    # URL, so a no-network declaration on it must be caught by the proxy.
    "node-fetcher": {
        "script": os.path.join(os.path.dirname(HERE), "seeded",
                               "node_fetcher.js"),
        "call_timeout": 30,
        "exercise": [
            ("scope", {}, True),
            ("grab", {"url": "https://example.com/"}, False),
        ],
        "skip_fuzz": True,
    },
    "malserver": {
        "launch": None,  # run as a script
        "script": MALSERVER,
        # Inside the sandbox image the fixture lives at a fixed path; an empty
        # list would mean "use the image CMD", a host path would not exist.
        "container_argv": ["python", "-u", "/app/malserver.py"],
        "exercise": [
            ("scope", {}, True),
            ("fetch_quote", {}, False),
            ("beacon", {}, False),
            ("sync", {}, False),
            ("telemetry", {}, False),
            ("save_note", {"text": "hello"}, False),
            ("run_helper", {}, False),
            ("roll", {}, True),
            ("lookup", {"word": "hello"}, False),
        ],
    },
}


def _from_pattern(pattern):
    """A shortest string matching a simple anchored regex, or None.

    Not a general regex engine and not trying to be. It handles the shapes
    that actually appear in tool schemas -- a literal prefix, a character
    class, a repetition count -- because `^rec-[0-9]{4}$` is a tool stating
    its input format precisely, and answering it with "test" throws away a
    call the tool would have served.
    """
    if not pattern:
        return None
    body = pattern
    if body.startswith("^"):
        body = body[1:]
    if body.endswith("$"):
        body = body[:-1]
    out, i = [], 0
    CLASSES = {"d": "0", "w": "a", "s": " ", "D": "a", "W": "-", "S": "a"}
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body):
            token, i = CLASSES.get(body[i + 1], body[i + 1]), i + 2
        elif ch == "[":
            close = body.find("]", i)
            if close < 0:
                return None
            inside = body[i + 1:close].lstrip("^")
            token = inside[0] if inside else "a"
            i = close + 1
        elif ch == ".":
            token, i = "a", i + 1
        elif ch in "()|":
            return None
        elif ch in "+*?":
            i += 1
            continue
        else:
            token, i = ch, i + 1
        if i < len(body) and body[i] == "{":
            close = body.find("}", i)
            if close < 0:
                return None
            count = body[i + 1:close].split(",")[0]
            i = close + 1
            try:
                token = token * int(count)
            except ValueError:
                return None
        elif i < len(body) and body[i] == "+":
            i += 1
        elif i < len(body) and body[i] in "*?":
            i += 1
            token = ""
        out.append(token)
    return "".join(out) or None


_FORMATS = {
    "date-time": "2026-01-02T03:04:05Z",
    "date": "2026-01-02",
    "time": "03:04:05",
    "email": "someone@example.com",
    "hostname": "example.com",
    "ipv4": "192.0.2.1",
    "uuid": "00000000-0000-4000-8000-000000000000",
    "uri": "https://example.com/",
    "url": "https://example.com/",
    "iri": "https://example.com/",
    "duration": "PT1S",
}


def _benign_arg(field_name, schema, depth=0):
    """A value the tool will actually accept, taken from its own schema.

    The schema is the tool stating what it wants. An earlier version of this
    read only `type` and the field NAME, and returned the string "test" for
    anything it did not recognise -- so a tool declaring
    `enum: [celsius, fahrenheit]` was handed "test", declined, and the harness
    recorded that the tool had done nothing.

    That is how a sweep of 280 published servers produced 835 verdict rows of
    which every single one was `not-covered`. The servers were fine. We were
    knocking with the wrong key and writing down that nobody was home -- and
    then reporting it as a finding about how hard MCP servers are to audit.

    Order matters: what the schema STATES beats what the schema constrains,
    which beats what the field is called. A name heuristic is the last resort,
    never the first.
    """
    schema = schema or {}

    # 1. The schema says the value outright.
    if "const" in schema:
        return schema["const"]
    if "default" in schema:
        return schema["default"]
    for key in ("examples", "example"):
        got = schema.get(key)
        if isinstance(got, list) and got:
            return got[0]
        if got not in (None, [], {}):
            return got
    if schema.get("enum"):
        return schema["enum"][0]
    for combinator in ("anyOf", "oneOf", "allOf"):
        options = schema.get(combinator)
        if isinstance(options, list) and options and depth < 3:
            return _benign_arg(field_name, options[0], depth + 1)

    kind = schema.get("type", "string")
    if isinstance(kind, list):
        kind = next((k for k in kind if k != "null"), "string")

    if kind == "array":
        # [] was the old answer for every array, so any tool needing something
        # to work on refused. Honour minItems, and supply one item regardless:
        # a summariser handed an empty list has nothing to summarise.
        items = schema.get("items") or {}
        count = max(1, int(schema.get("minItems") or 1))
        return [_benign_arg(field_name, items, depth + 1) for _ in range(count)]

    if kind == "object":
        props = schema.get("properties") or {}
        required = schema.get("required") or list(props)
        if depth >= 3:
            return {}
        return {k: _benign_arg(k, props.get(k, {}), depth + 1)
                for k in required if k in props}

    if kind == "boolean":
        return False

    if kind in ("integer", "number"):
        for bound in ("minimum", "exclusiveMinimum"):
            if isinstance(schema.get(bound), (int, float)):
                value = schema[bound] + (1 if bound.startswith("exclusive")
                                         else 0)
                return int(value) if kind == "integer" else value
        return 1

    # 2. The schema constrains the value.
    fmt = (schema.get("format") or "").lower()
    if fmt in _FORMATS:
        return _FORMATS[fmt]
    from_pattern = _from_pattern(schema.get("pattern"))
    if from_pattern:
        return from_pattern

    # 3. Last resort: what the field is called.
    n = (field_name or "").lower()
    if any(k in n for k in ("url", "uri", "link", "endpoint")):
        return "https://example.com/"
    if any(k in n for k in ("repo", "repository")):
        return GITREPO
    if any(k in n for k in ("path", "file", "dir", "folder")):
        return FIXTURES
    if any(k in n for k in ("timezone", "tz")):
        return "America/New_York"
    if any(k in n for k in ("email", "mail")):
        return "someone@example.com"
    if any(k in n for k in ("date", "time", "when")):
        return "2026-01-02T03:04:05Z"
    if any(k in n for k in ("query", "search", "term", "keyword")):
        return "example"
    value = "test"
    minimum = schema.get("minLength")
    if isinstance(minimum, int) and minimum > len(value):
        value = value + "x" * (minimum - len(value))
    return value


def _alternate_arg(field_name, schema, depth=0):
    """A DIFFERENT valid value for the same argument.

    Paired with `_benign_arg`, this is how the harness finds out whether a tool
    computed anything. A tool that returns the same bytes for "America/
    New_York" and for "Asia/Tokyo" is not answering the question; a tool whose
    answer moves with the argument did real work, whether or not it touched a
    socket or a file.
    """
    schema = schema or {}
    if "const" in schema:
        return schema["const"]                      # genuinely has one value
    enum = schema.get("enum")
    if enum:
        return enum[1] if len(enum) > 1 else enum[0]

    kind = schema.get("type", "string")
    if isinstance(kind, list):
        kind = next((k for k in kind if k != "null"), "string")

    if kind == "array":
        items = schema.get("items") or {}
        count = max(1, int(schema.get("minItems") or 1))
        return [_alternate_arg(field_name, items, depth + 1)
                for _ in range(count)]
    if kind == "object":
        props = schema.get("properties") or {}
        required = schema.get("required") or list(props)
        if depth >= 3:
            return {}
        return {k: _alternate_arg(k, props.get(k, {}), depth + 1)
                for k in required if k in props}
    if kind == "boolean":
        return True                                  # _benign_arg gives False
    if kind in ("integer", "number"):
        base = _benign_arg(field_name, schema, depth)
        try:
            return base + 1
        except TypeError:
            return 2

    fmt = (schema.get("format") or "").lower()
    alternates = {
        "date-time": "2019-07-08T09:10:11Z", "date": "2019-07-08",
        "time": "09:10:11", "email": "other@example.net",
        "hostname": "example.net", "ipv4": "198.51.100.7",
        "uuid": "11111111-1111-4111-8111-111111111111",
        "uri": "https://example.net/other", "url": "https://example.net/other",
        "iri": "https://example.net/other", "duration": "PT2S",
    }
    if fmt in alternates:
        return alternates[fmt]
    if schema.get("pattern"):
        # A pattern usually pins the shape exactly; varying it risks becoming
        # invalid, and an invalid second call proves nothing. Reuse it and let
        # the other arguments carry the variation.
        return _benign_arg(field_name, schema, depth)

    n = (field_name or "").lower()
    if any(k in n for k in ("timezone", "tz")):
        return "Asia/Tokyo"
    if any(k in n for k in ("url", "uri", "link", "endpoint")):
        return "https://example.net/other"
    if any(k in n for k in ("email", "mail")):
        return "other@example.net"
    if any(k in n for k in ("date", "time", "when")):
        return "2019-07-08T09:10:11Z"
    return "second"


def _mark(value, marker):
    """Put the canary INSIDE a value the tool is given.

    This is the whole counterfactual. Watching a request tells you a request
    happened; finding the marker you put in the tool's INPUT inside that
    request is what tells you the request carried your data.

    It was previously planted only in SAYDO_CANARY, an environment variable,
    and the seeded fixture read it from there and exfiltrated it. So the test
    demonstrated that a fixture reads an env var -- the same mechanism the
    prior art uses -- and never once looked at whether a real tool passes its
    ARGUMENTS out. Across 279 third-party servers the proxy was hunting a
    string that had never been in any data any tool was given, and every one
    came back unexamined.

    Strings carry it inline so they stay plausible input. Structures carry it
    in their members. Numbers and booleans cannot carry it and are left alone.
    """
    if not marker:
        return value
    if isinstance(value, str):
        # Appended rather than substituted, so an enum, a date or a pattern
        # stays valid and the tool still accepts the call. A tool that
        # validates strictly may reject the marked value; that shows up as the
        # call failing, which is visible, rather than as a silent non-result.
        return value + "-" + marker if value else marker
    if isinstance(value, list):
        return [_mark(v, marker) for v in value]
    if isinstance(value, dict):
        return {k: _mark(v, marker) for k, v in value.items()}
    return value


def synth_plan(capture, command_argv, timeout=30, marker=None):
    """A generic exercise for a server with no hand-written plan: call each
    tool once with benign arguments, behind the boundary proxy and the audit
    hook, so egress / writes / subprocess are observed under normal use.

    It is a LOWER BOUND on findings: a tool that needs a specific valid input
    to act (a real repo, a real query) may do little under a placeholder and
    pass invariants it would fail with real input. The sweep reports it as
    such rather than as a clean bill.
    """
    exercise, variation = [], []
    for t in capture["tools"]:
        name = t["name"]
        schema = t["definition"].get("inputSchema", {}) or {}
        props = schema.get("properties", {}) or {}
        required = schema.get("required", list(props))
        args = {k: _mark(_benign_arg(k, props.get(k, {})), marker)
                for k in required}
        deterministic = (name.lower() in ("scope", "guard", "about")
                         and not required)
        exercise.append((name, args, deterministic))
        # A second call with DIFFERENT valid arguments. Its only purpose is to
        # find out whether the tool computes: an answer that moves with the
        # input is work, even when nothing was written and no socket opened.
        # Without it, every pure-computation server -- which is most good ones
        # -- looked identical to a server that declines everything.
        if required:
            other = {k: _mark(_alternate_arg(k, props.get(k, {})), marker)
                     for k in required}
            if other != args:
                variation.append((name, other))
    return {"command_argv": list(command_argv), "exercise": exercise,
            "variation": variation,
            "call_timeout": timeout, "skip_fuzz": True, "synthetic": True}


def write_fixtures():
    os.makedirs(FIXTURES, exist_ok=True)
    if not os.path.exists(TINY_MM):
        with open(TINY_MM, "w", encoding="ascii", newline="\n") as fh:
            fh.write(
                "$( A minimal Metamath database for harness exercise. $)\n"
                "$c ( ) -> wff |- $.\n"
                "$v p q $.\n"
                "wp $f wff p $.\n"
                "wq $f wff q $.\n"
                "wi $a wff ( p -> q ) $.\n"
                "ax-1 $a |- ( p -> ( q -> p ) ) $.\n"
                "th1 $p |- ( p -> ( q -> p ) ) $= wp wq ax-1 $.\n")
    if not os.path.exists(SAMPLE_DOC):
        with open(SAMPLE_DOC, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("A short plain document.\n\nIt exists so scan_document "
                     "has a real local file to read under observation.\n")
    # A real git repository, so a git server has something to operate on.
    # Without it, git tools error on a non-repo path and the sweep sees
    # nothing -- a false clean bill. Best effort: skip if git is absent.
    if not os.path.isdir(os.path.join(GITREPO, ".git")):
        import subprocess
        try:
            os.makedirs(GITREPO, exist_ok=True)
            env = dict(os.environ,
                       GIT_AUTHOR_NAME="saydo", GIT_AUTHOR_EMAIL="s@saydo",
                       GIT_COMMITTER_NAME="saydo", GIT_COMMITTER_EMAIL="s@saydo")
            run = lambda *a: subprocess.run(["git", "-C", GITREPO, *a],
                                            env=env, capture_output=True)
            run("init", "-q")
            with open(os.path.join(GITREPO, "README.md"), "w",
                      encoding="utf-8", newline="\n") as fh:
                fh.write("# fixture repo\n")
            run("add", "-A")
            run("commit", "-q", "-m", "fixture")
        except Exception:
            pass

    os.makedirs(SOUNDS_DIR, exist_ok=True)
    for name in ("alpha.wav", "bravo.wav"):
        p = os.path.join(SOUNDS_DIR, name)
        if not os.path.exists(p):
            # Filenames are what build_soundboard reads; a minimal WAV header
            # is enough for a real file on disk without shipping audio.
            with open(p, "wb") as fh:
                fh.write(b"RIFF\x24\x00\x00\x00WAVEfmt \x10\x00\x00\x00"
                         b"\x01\x00\x01\x00\x44\xac\x00\x00\x88\x58\x01\x00"
                         b"\x02\x00\x10\x00data\x00\x00\x00\x00")


if __name__ == "__main__":
    write_fixtures()
    print(json.dumps(sorted(PLANS), indent=2))
