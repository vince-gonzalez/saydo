"""Give a server the credentials it asks for, so that it does something.

The corpus kept returning nothing. Thirteen servers started, thirteen did
nothing observable, and the reason was not subtle: almost no MCP server will
act without a credential. Handed none, they reject every call before doing any
work, and a harness watching that learns only that it was refused.

A well-formed fake credential fixes this, because the interesting event happens
before the credential is ever checked. A server given a syntactically valid key
builds its request and sends it. The proxy sees the destination and the body.
Whether the far end would have accepted the key is irrelevant -- by then we
already know where your input was going.

Four rules, and the last two are the ones that keep this safe to run.

ONLY WHAT THE SOFTWARE NAMES. Variables come from the program's own words: its
startup complaint, its README, its manifest. Nothing is guessed and nothing is
sprayed. Setting variables a program never asked for changes its behaviour and
then reports the result as the program's.

RECOGNISABLY FAKE, STILL WELL FORMED. Values pass shape validation and could
not be mistaken for real credentials by a person reading a log: test prefixes,
reserved example domains, and an embedded marker naming this project. Nothing
here authenticates anywhere.

NEVER A VARIABLE THAT DISARMS THE HARNESS. A README that mentions NODE_OPTIONS
or PYTHONPATH or HTTPS_PROXY is describing the exact variables the monitor and
the egress proxy are installed through. Honouring those would unhook the
observer and produce a clean run because nothing was watching. They are refused
by name.

ACTED IS NOT SUCCEEDED. A synthetic credential is rejected upstream, so a run
under one shows what the server DOES with input, never that its work
succeeded. Runs carry `syntheticCredentials` so no report can quietly read one
as a successful workload.

The credential carries its own marker, distinct from the input canary. If a key
appears in egress, the server transmitted its own credential -- a different
finding from carrying the caller's data, and one that must not be confused with
it, since the canary's whole job is to change between runs.
"""

from __future__ import annotations

import re
import secrets

#: Distinct from canary.MARKER_PREFIX on purpose. A credential leaving is not
#: the same event as the caller's input leaving, and the counterfactual reads
#: the canary specifically -- mixing them would make a transmitted key look
#: like input-dependent egress in every run.
CRED_PREFIX = "SAYDO-CRED-"

#: Variables the harness itself travels through. Setting any of these from a
#: README would disable the monitor, bypass the recording proxy, or move the
#: server off the scratch mount -- and the run would come back clean because
#: nothing was observing it, which is the most dangerous possible failure here.
NEVER_SET = frozenset("""
    PATH HOME USER SHELL PWD OLDPWD TMPDIR TEMP TMP
    LD_PRELOAD LD_LIBRARY_PATH DYLD_INSERT_LIBRARIES
    PYTHONPATH PYTHONSTARTUP PYTHONHOME PYTHONDONTWRITEBYTECODE
    NODE_OPTIONS NODE_PATH NODE_EXTRA_CA_CERTS NODE_USE_ENV_PROXY
    HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY
    http_proxy https_proxy all_proxy no_proxy
    SSL_CERT_FILE SSL_CERT_DIR REQUESTS_CA_BUNDLE CURL_CA_BUNDLE
    GIT_SSH_COMMAND BASH_ENV ENV IFS
""".split())

#: Contexts that identify a name AS an environment variable. A token appearing
#: in one of these is one, whatever it looks like, so the name pattern can stay
#: loose here without matching ordinary prose.
NAMED_IN_CONTEXT = (
    r"process\.env\.([A-Z][A-Z0-9_]{2,})",
    r"process\.env\[[\"']([A-Z][A-Z0-9_]{2,})[\"']\]",
    r"os\.environ(?:\.get)?\(?\[?[\"']([A-Z][A-Z0-9_]{2,})[\"']",
    r"os\.getenv\([\"']([A-Z][A-Z0-9_]{2,})[\"']",
    r"\bexport\s+([A-Z][A-Z0-9_]{2,})\s*=",
    r"\$\{([A-Z][A-Z0-9_]{2,})\}",
    r"(?:^|\s)-e\s+([A-Z][A-Z0-9_]{2,})=",
    # The server's own complaint, which is the highest-signal source we get
    # and costs nothing: it is printed on the first refused call.
    r"[Mm]issing (?:required )?(?:the )?(?:env(?:ironment)? var(?:iable)?[: ]+)?"
    r"[\"']?([A-Z][A-Z0-9_]{2,})[\"']?",
    r"[\"']?([A-Z][A-Z0-9_]{2,})[\"']? (?:is |was )?(?:not set|required|missing)",
    r"[Pp]lease set (?:the )?[\"']?([A-Z][A-Z0-9_]{2,})[\"']?",
    r"[Ss]et (?:the )?[\"']?([A-Z][A-Z0-9_]{2,})[\"']? (?:environment|env)",
    r"[Rr]equires? (?:the )?[\"']?([A-Z][A-Z0-9_]{2,})[\"']? (?:environment|env)",
    # `"env": {"FOO": "..."}` in an MCP client config, which is how these are
    # documented for users to paste into a settings file.
    r"[\"']([A-Z][A-Z0-9_]{2,})[\"']\s*:\s*[\"'][^\"']*(?:your|xxx|<|\.\.\.)",
)

#: Words that pass the shape test and are not credentials. Each appears in real
#: package READMEs in this corpus.
NOT_A_SECRET = frozenset("""
    README LICENSE MIT ISC BSD API MCP JSON YAML HTTP HTTPS URL URI
    TODO FIXME NOTE WARNING ERROR INFO DEBUG TRACE
    GET POST PUT PATCH DELETE HEAD OPTIONS
    AND OR NOT FOR THE YOU YOUR WITH FROM THIS THAT WILL CAN MUST
""".split())

#: Suffixes that make a bare all-caps token credible as a credential name when
#: nothing in the surrounding syntax marks it as an environment variable.
CREDENTIAL_ISH = ("_KEY", "_TOKEN", "_SECRET", "_PASSWORD", "_PASS", "_URL",
                  "_URI", "_DSN", "_ENDPOINT", "_HOST", "_ID", "_ACCOUNT",
                  "_EMAIL", "_USER", "_USERNAME", "_REGION", "_BUCKET",
                  "_PROJECT", "_ORG", "_WORKSPACE", "_DOMAIN", "_APIKEY",
                  "_CREDENTIALS", "_AUTH", "_SESSION", "_COOKIE", "_WEBHOOK")

_BARE = re.compile(r"\b([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)\b")

#: A documented value that is really a fill-in-the-blank. Reusing one of these
#: hands the server the literal string "<YOUR_TOKEN_HERE>".
_PLACEHOLDER = re.compile(
    r"^\s*$|<|>|\.\.\.|xxx|your|change[ _-]?me|here|placeholder|todo|"
    r"^example$|^tbd$|^\{\{", re.I)


def _documented(text, name):
    """The value the software's own docs put next to this variable.

    A server that documents `-e LOG_LEVEL=debug` is telling us what it wants,
    and inventing a random string there is worse than useless: some programs
    validate these and exit, which puts us back to observing nothing. The
    documented value is only ever used for settings, never for credentials --
    a README containing a real-looking key is a leaked key, and replaying it
    would mean transmitting someone's actual credential from this harness.
    """
    for pattern in (r"{}\s*=\s*[\"']?([^\"'\s,}}\n]+)".format(re.escape(name)),
                    r"[\"']{}[\"']\s*:\s*[\"']([^\"']*)[\"']".format(
                        re.escape(name))):
        hit = re.search(pattern, text)
        if hit and not _PLACEHOLDER.search(hit.group(1)):
            return hit.group(1)
    return None


#: How software reveals the shape it expects. A generic opaque value is
#: rejected by any client that validates a prefix, which puts the server back
#: to observing nothing -- so the shape has to be learned rather than guessed,
#: and the place it is stated is the refusal itself:
#:
#:     "Incorrect API key provided. Your key should start with `sk-`."
#:
#: That message is free. It arrives on the first refused call, which is exactly
#: the call a first pass makes.
_SHAPE_HINTS = (
    r"(?:should|must|needs? to|has to) (?:start|begin) with[:\s]+"
    r"[\"'`]?([A-Za-z][A-Za-z0-9]{1,11}[-_])",
    r"(?:prefixed?|prefix) (?:with|of|is)[:\s]+[\"'`]?"
    r"([A-Za-z][A-Za-z0-9]{1,11}[-_])",
    r"(?:format|form|looks? like)[:\s]+[\"'`]?"
    r"([A-Za-z][A-Za-z0-9]{1,11}[-_])[A-Za-z0-9x*.<]",
)

#: An example value whose prefix is real even though its body is a placeholder:
#: `sk-proj-xxxxxxxx`, `ghp_xxxxxxxx`. The prefix is the part that gets
#: validated, so it is worth taking even from a redacted example.
_EXAMPLE_PREFIX = re.compile(r"^([A-Za-z][A-Za-z0-9]{1,11}[-_]"
                             r"(?:[A-Za-z][A-Za-z0-9]{1,11}[-_])?)")

#: Values that are prose telling the reader to substitute something, whose
#: leading words would otherwise be mistaken for a prefix.
_PROSE_VALUE = re.compile(r"^(?:your|my|the|an?|insert|enter|add|paste|"
                          r"example|sample|dummy|fake|test)[-_]", re.I)


def shape_prefix(name, *texts):
    """The prefix this credential is expected to carry, if anything says so.

    Learned, never assumed. Two sources, both the software's own words: a
    refusal that states the expected form, and a documented example whose
    body is redacted but whose prefix is not.
    """
    for text in texts:
        if not text:
            continue
        window = text
        # Prefer a hint stated near this variable's own name, so a README
        # documenting several keys does not give them all the first prefix.
        spot = text.find(name)
        if spot != -1:
            window = text[max(0, spot - 200):spot + 400]
        for pattern in _SHAPE_HINTS:
            hit = re.search(pattern, window)
            if hit:
                return hit.group(1)
        for pattern in (r"{}\s*=\s*[\"'`]?([^\"'`\s,}}\n]+)".format(
                            re.escape(name)),
                        r"[\"']{}[\"']\s*:\s*[\"']([^\"']+)[\"']".format(
                            re.escape(name))):
            hit = re.search(pattern, text)
            if not hit or _PROSE_VALUE.search(hit.group(1)):
                continue
            example = _EXAMPLE_PREFIX.match(hit.group(1))
            if example:
                return example.group(1)
    return None


def _is_credential(name):
    upper = name.upper()
    return any(w in upper for w in ("KEY", "TOKEN", "SECRET", "PASSWORD",
                                    "PASS", "AUTH", "CREDENTIAL", "COOKIE",
                                    "SESSION", "PRIVATE", "SIGNATURE"))


def new_marker():
    """A per-run marker, so a leaked credential names the run that planted it."""
    return CRED_PREFIX + secrets.token_hex(8)


def wanted(*texts):
    """Environment variables the software itself named, with the evidence.

    Returns [{"name", "evidence", "confidence"}]. `named` means the syntax
    around it said it was an environment variable; `shape` means only the name
    suggested it, which is weaker and is kept separate so a caller can decide
    how much to trust it.
    """
    found, seen = [], set()

    def add(name, confidence, evidence):
        name = name.strip()
        if not name or name in seen:
            return
        if name in NEVER_SET or name in NOT_A_SECRET:
            return
        if name.startswith("SAYDO"):
            return
        seen.add(name)
        entry = {"name": name, "confidence": confidence,
                 "evidence": evidence[:120].strip()}
        if not _is_credential(name):
            documented = None
            for source in texts:
                documented = documented or (source and
                                            _documented(source, name))
            if documented:
                entry["documented"] = documented
        found.append(entry)

    for text in texts:
        if not text:
            continue
        for pattern in NAMED_IN_CONTEXT:
            for hit in re.finditer(pattern, text):
                start = max(0, hit.start() - 30)
                add(hit.group(1), "named", text[start:hit.end() + 20])

    for text in texts:
        if not text:
            continue
        for hit in _BARE.finditer(text):
            name = hit.group(1)
            if any(name.endswith(s) for s in CREDENTIAL_ISH):
                start = max(0, hit.start() - 30)
                add(name, "shape", text[start:hit.end() + 20])
    return found


def _value_for(name, marker, prefix=None):
    """A value shaped like the real thing and obviously not one.

    Shape matters because servers validate it: a key that fails a prefix check
    is rejected in the client before any request is built, and the run goes
    back to showing nothing. Every value is still unmistakably synthetic to a
    person, and none of them authenticate anywhere.
    """
    upper = name.upper()
    tail = marker.replace(CRED_PREFIX, "")

    def pad(prefix, width):
        body = (tail + "0" * width)[:width]
        return prefix + body

    # A shape the software stated outranks every rule below it. Those rules
    # are knowledge about well-known vendors; this is the program telling us
    # what it will accept, and it is right when they disagree.
    if prefix:
        return pad(prefix + "notreal", 32)

    if "OPENAI" in upper:
        return pad("sk-notreal", 48)
    if "ANTHROPIC" in upper:
        return pad("sk-ant-notreal", 40)
    if "GITHUB" in upper or upper.startswith("GH_"):
        return pad("ghp_notreal", 36)
    if "SLACK" in upper:
        return pad("xoxb-notreal-", 24)
    # Stripe publishes a `sk_test_` namespace that cannot touch live data, so
    # the fake is unmistakable to anyone who knows the format.
    if "STRIPE" in upper:
        return pad("sk_test_notreal", 24)
    if "AWS" in upper and "SECRET" in upper:
        return pad("wJalrNOTREAL", 40)
    if "AWS" in upper:
        return pad("AKIANOTREAL", 20)
    if upper.endswith("_EMAIL") or "EMAIL" in upper:
        # RFC 2606 reserves example.com; it cannot be registered by anyone.
        return "saydo-{}@example.com".format(tail[:8])
    # Checked before the URL suffixes: a connection string is recognised by
    # the engine named in it, not by how the variable happens to end.
    # POSTGRES_CONNECTION_STRING ends in _STRING and anything parsing it as a
    # DSN dies on an opaque token, which puts the server right back to doing
    # nothing observable.
    if "POSTGRES" in upper or "PGSQL" in upper:
        return "postgresql://saydo:{}@db.example.com:5432/saydo".format(tail[:8])
    if "MONGO" in upper:
        return "mongodb://saydo:{}@db.example.com:27017/saydo".format(tail[:8])
    if "REDIS" in upper:
        return "redis://saydo:{}@db.example.com:6379/0".format(tail[:8])
    if "MYSQL" in upper or "MARIADB" in upper:
        return "mysql://saydo:{}@db.example.com:3306/saydo".format(tail[:8])
    if ("DATABASE" in upper or upper.endswith(("_DSN", "_CONN"))
            or "CONNECTION_STRING" in upper):
        return "postgresql://saydo:{}@db.example.com:5432/saydo".format(tail[:8])
    if upper.endswith(("_URL", "_URI", "_ENDPOINT", "_WEBHOOK")):
        return "https://example.com/saydo/{}".format(tail[:8])
    if upper.endswith(("_HOST", "_DOMAIN")):
        return "example.com"
    if upper.endswith("_PORT"):
        return "8080"
    if upper.endswith("_REGION"):
        return "us-east-1"
    if upper.endswith(("_USER", "_USERNAME")):
        return "saydo-{}".format(tail[:8])
    if upper.endswith(("_PASSWORD", "_PASS")):
        return "notreal-{}".format(tail[:12])
    if upper.endswith("_ID") or "UUID" in upper:
        # A UUID-shaped value, because id fields are commonly parsed as one.
        h = (tail + "0" * 32)[:32]
        return "{}-{}-4{}-8{}-{}".format(h[:8], h[8:12], h[12:15],
                                         h[16:19], h[20:32])
    if upper.endswith("_JSON") or "CREDENTIALS" in upper:
        return '{"type":"saydo-synthetic","marker":"%s"}' % marker
    return pad("notreal-", 40)


def synthesize(names, marker, *texts):
    """Values for the named variables. Refuses anything that disarms the run.

    Pass the software's own text -- its refusal, its README -- and any shape it
    states is honoured. Without that, an unknown vendor gets a generic opaque
    value, which a client validating a prefix rejects, leaving the server as
    silent as it was before.
    """
    out = {}
    for entry in names:
        name = entry["name"] if isinstance(entry, dict) else entry
        if name in NEVER_SET or name.startswith("SAYDO"):
            continue
        documented = (entry.get("documented")
                      if isinstance(entry, dict) else None)
        # Settings take the value their own docs give them; credentials are
        # always synthesized, so nothing real is ever replayed.
        if documented:
            out[name] = documented
        else:
            out[name] = _value_for(name, marker,
                                   shape_prefix(name, *texts) if texts else None)
    return out


def check():
    """Problems with this module, for the selfcheck gate. [] = good."""
    problems = []
    marker = new_marker()

    # 1. The variables the harness travels through must never be honoured,
    #    however plausibly a README asks for them. This is the failure that
    #    produces a clean report because nothing was watching.
    hostile = ("Set NODE_OPTIONS to enable the plugin. "
               "export PYTHONPATH=/opt/lib\n"
               "process.env.HTTPS_PROXY = 'http://attacker.example'\n"
               "Missing required LD_PRELOAD")
    for entry in wanted(hostile):
        if entry["name"] in NEVER_SET:
            problems.append(
                "{} was accepted from a README; honouring it would unhook the "
                "monitor or the proxy and the run would come back clean "
                "because nothing observed it".format(entry["name"]))
    if synthesize([{"name": "NODE_OPTIONS"}, {"name": "PATH"}], marker):
        problems.append("synthesize() produced a value for a variable that "
                        "the harness itself travels through")

    # 2. The server's own complaint is the cheapest source and must work.
    complaint = "Error: Missing required environment variable: OPENAI_API_KEY"
    names = [e["name"] for e in wanted(complaint)]
    if "OPENAI_API_KEY" not in names:
        problems.append("the variable named in a server's own startup "
                        "complaint was not picked up")

    # 3. Shape validation is the whole point: a value that fails a prefix
    #    check is rejected before any request is built, and the run shows
    #    nothing again.
    values = synthesize([{"name": "OPENAI_API_KEY"}, {"name": "GITHUB_TOKEN"},
                         {"name": "STRIPE_SECRET_KEY"},
                         {"name": "DATABASE_URL"}], marker)
    if not values.get("OPENAI_API_KEY", "").startswith("sk-"):
        problems.append("the OpenAI-shaped value would fail a prefix check")
    if not values.get("GITHUB_TOKEN", "").startswith("ghp_"):
        problems.append("the GitHub-shaped value would fail a prefix check")
    if not values.get("STRIPE_SECRET_KEY", "").startswith("sk_test_"):
        problems.append("the Stripe-shaped value is not in the test namespace, "
                        "so it does not read as unmistakably fake")
    if "example.com" not in values.get("DATABASE_URL", ""):
        problems.append("a synthesized URL points somewhere other than a "
                        "reserved example domain")

    # 4. Every value must be traceable to the run that planted it, or a
    #    credential found in egress cannot be tied to anything.
    for name, value in values.items():
        if marker.replace(CRED_PREFIX, "")[:8] not in value:
            problems.append("{} carries no run marker, so if it appears in "
                            "egress it cannot be attributed".format(name))

    # 5. A setting takes the value its own docs give it. Inventing a random
    #    string for LOG_LEVEL is worse than doing nothing: programs that
    #    validate it exit, and the run observes nothing again.
    docs = "docker run -e LOG_LEVEL=debug -e AWS_REGION=eu-west-2 img"
    settings = synthesize(wanted(docs), marker)
    if settings.get("LOG_LEVEL") != "debug":
        problems.append("LOG_LEVEL was given {!r} instead of the documented "
                        "value, which programs that validate it reject"
                        .format(settings.get("LOG_LEVEL")))

    # 6. A README containing a real-looking key is a leaked key. Replaying it
    #    would mean this harness transmitting someone's actual credential.
    leaked = 'export OPENAI_API_KEY=sk-proj-Th1sLooksRealAndMustNotBeReused'
    replayed = synthesize(wanted(leaked), marker)
    if "Th1sLooksReal" in replayed.get("OPENAI_API_KEY", ""):
        problems.append("a credential found in documentation was replayed; "
                        "this harness must never transmit a real key")

    # 7. A connection string is recognised by its engine, not its suffix.
    dsn = synthesize([{"name": "POSTGRES_CONNECTION_STRING"}], marker)
    if not dsn["POSTGRES_CONNECTION_STRING"].startswith("postgresql://"):
        problems.append("a connection string was given an opaque token, which "
                        "anything parsing it as a DSN rejects")

    # 8. Ordinary prose must not become a credential request.
    noisy = "The API returns JSON. See the README for HTTP GET and POST usage."
    invented = [e["name"] for e in wanted(noisy)]
    if invented:
        problems.append("invented {} from prose that names no environment "
                        "variable".format(invented))
    return problems


if __name__ == "__main__":
    import sys
    found = check()
    for line in found:
        print("  " + line)
    print("credentials: {}".format("all hold" if not found
                                   else "{} PROBLEM(S)".format(len(found))))
    sys.exit(1 if found else 0)
