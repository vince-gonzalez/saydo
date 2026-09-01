"""Sort servers into domains, so a finding has a denominator.

"156 servers send their input somewhere" is a number without a scale. "Of the
servers that handle money, N promise to keep data local and contact a third
party anyway" is a finding, because it says who is affected and how much it
costs them. Same measurements; the difference is entirely the denominator.

That makes the classifier load-bearing in a way keyword matching usually is
not. Every server put in a bucket here is a real project, and a category is
carried into a sentence about behaviour, so a wrong bucket is not noise -- it
files someone under "handles money" who does not.

Four rules keep this a census rather than a guess.

EVIDENCE, NOT SCORES. Every assignment records the exact phrase that caused
it. A reader checks the reading instead of trusting the classifier, and a bad
rule is visible as a list of bad quotes rather than hidden in a total.

NO FORCE-FIT. A server matching nothing is `uncategorised` and is counted and
reported. Assigning everything to its nearest bucket would inflate every
denominator with servers that do not belong in one, which quietly shrinks
every rate computed from them.

MEMBERSHIP OVERLAPS. A Stripe server that writes files is finance AND
filesystem. Forcing a primary category would misfile it under whichever rule
happened to sort first, so a server may hold several and the report says so.
Category counts therefore sum to more than the population, on purpose.

NEAR-MISSES ARE EXCLUDED BY NAME. `healthcheck` is not medicine, a `databank`
is not a bank, `tokenizer` has nothing to do with credentials, and a
`taxonomy` is not tax. Each of these appears in the real corpus. They are
listed as exclusions and covered by tests, because the failure they cause --
a server filed under a sensitive category it has nothing to do with -- is
exactly the kind this project exists to avoid making.
"""

from __future__ import annotations

import io
import json
import re
import sys

#: Categories whose servers hold something worth losing. A promise broken here
#: is not the same finding as a broken promise in a dice-rolling server, and
#: the report separates them for that reason.
SENSITIVE = ("finance", "health", "credentials", "shell-exec", "filesystem",
             "messaging", "personal-data")

#: (category, pattern, why-it-counts). Patterns run against name + description
#: lowercased. Word boundaries throughout: substring matching is what produces
#: a `taxonomy` filed under tax.
RULES = (
    ("finance", r"\b(?:payment|payments|invoice|invoicing|billing)\b",
     "moves or records money"),
    ("finance", r"\b(?:stripe|paypal|square|plaid|quickbooks|xero)\b",
     "integrates a payment or accounting provider"),
    ("finance", r"\b(?:trading|brokerage|portfolios?|equities|securities|invest(?:ing|ment|ments)?)\b",
     "acts on financial markets"),
    ("finance", r"\b(?:bank|banks|banking)\b", "connects to a bank"),
    ("finance", r"\b(?:accounting|payroll|ledgers?|bookkeeping)\b",
     "keeps financial records"),
    ("finance", r"\btax(?:es)?\b", "handles tax data"),
    ("finance",
     r"\b(?:crypto|cryptocurrency|wallet|blockchain|defi|ethereum|bitcoin|"
     r"solana|web3)\b", "holds or moves crypto assets"),

    ("health", r"\b(?:patients?|clinical|medical|medicine|diagnoses)\b",
     "handles patient or clinical data"),
    ("health", r"\b(?:ehr|emr|fhir|hl7|hipaa|icd-?10|snomed)\b",
     "speaks a medical records standard"),
    ("health", r"\b(?:diagnosis|diagnostic|prescription|prescribing)\b",
     "concerns diagnosis or prescribing"),
    ("health", r"\b(?:health|healthcare)\b", "describes itself as health"),

    ("credentials", r"\b(?:password|passwords|passphrase)\b",
     "handles passwords"),
    ("credentials", r"\b(?:credential|credentials|secret|secrets)\b",
     "handles credentials or secrets"),
    ("credentials", r"\b(?:vault|keychain|keyring|1password|bitwarden)\b",
     "reads a secret store"),
    ("credentials", r"\b(?:api[- ]key|access[- ]token|auth[- ]token|oauth)\b",
     "handles API keys or auth tokens"),

    ("shell-exec", r"\b(?:shell|bash|zsh|powershell|terminal|tty)\b",
     "runs shell commands"),
    ("shell-exec",
     r"\b(?:command execution|execute commands?|run commands?|subprocess)\b",
     "executes commands"),

    # `\bfiles?\b` alone matches nearly every server in the corpus -- they all
    # mention a file somewhere. These require a verb or a noun phrase that
    # means the server itself touches the disk.
    ("filesystem", r"\b(?:filesystem|file system)s?\b",
     "reads or writes files"),
    ("filesystem",
     r"\bfile (?:operations|management|access|browsing|editing|i/?o)\b",
     "reads or writes files"),
    ("filesystem",
     r"\b(?:read|reads|reading|write|writes|writing|edit|edits|editing|"
     r"manage|manages|access|accesses|list|lists) "
     r"(?:\w+ )?(?:local |your )?(?:files?|directories|directory|folders?)\b",
     "reads or writes files"),
    ("filesystem", r"\b(?:local|your) (?:files?|filesystem|disk)\b",
     "reads or writes files"),

    ("messaging", r"\b(?:slack|discord|telegram|whatsapp|teams)\b",
     "posts to a chat platform"),
    ("messaging",
     r"\b(?:emails?|e-mails?|gmail|smtp|imap|mailboxe?s?|sendgrid|postmark|"
     r"mailgun)\b", "sends or reads mail"),
    ("messaging", r"\b(?:sms|twilio)\b", "sends messages"),

    ("personal-data", r"\b(?:contacts|calendars?|crm|address books?|todo list|tasks? list)\b",
     "holds personal records"),
    ("personal-data", r"\b(?:notion|obsidian|evernote|journal|diary)\b",
     "holds personal notes"),
    ("personal-data", r"\b(?:location|gps|geolocation)\b",
     "handles location data"),
    ("personal-data", r"\b(?:photos?|camera roll|screenshots?)\b",
     "handles personal media"),

    ("browser", r"\b(?:browsers?|playwright|puppeteer|selenium|chromium|headless chrome)\b",
     "drives a browser"),
    ("browser", r"\b(?:scrape|scraping|scraper|crawl|crawler)\b",
     "fetches remote pages"),

    ("database", r"\b(?:postgres|postgresql|mysql|sqlite|mongodb|redis|"
     r"clickhouse|snowflake|bigquery)\b", "connects to a database"),
    ("database", r"\b(?:databases?|sql)\b", "connects to a database"),

    ("cloud-infra", r"\b(?:aws|gcp|azure|kubernetes|k8s|terraform|docker)\b",
     "controls infrastructure"),
    ("cloud-infra", r"\b(?:deploy|deployment|provisioning)\b",
     "changes deployed systems"),

    ("dev-tools", r"\b(?:github|gitlab|bitbucket|jira|linear|sentry)\b",
     "acts on a development platform"),
    ("dev-tools", r"\b(?:lint|linter|debugger|compiler|test runner)\b",
     "works on code"),

    ("search-web", r"\b(?:search engine|web search|google search|brave "
     r"search|serp)\b", "queries the web"),
    ("ai-model", r"\b(?:llm|openai|anthropic|gemini|ollama|embedding|"
     r"embeddings)\b", "calls a model provider"),
)

#: Phrases that contain a category term but mean something else. Each one was
#: found in the real corpus, and each would file a server under a sensitive
#: category it has nothing to do with. They are removed from the text BEFORE
#: any rule runs, so `healthcheck` cannot make a monitoring tool medical.
EXCLUSIONS = (
    # A liveness probe is not medicine. This is the single most common
    # false positive in the corpus -- nearly every server mentions one.
    r"health[- ]?check(?:s|ing)?", r"healthz",
    r"\bcode[- ]?health\b", r"\brepo(?:sitory)? health\b", r"\bhealth status\b",
    r"\bhealth endpoint\b", r"\bsystem health\b", r"\bservice health\b",
    # A store of data is not a bank.
    r"\bdata ?bank\b", r"\bword ?bank\b", r"\bimage ?bank\b", r"\bmemory bank\b",
    # LLM tokens are not credentials, and this corpus is full of them.
    r"\btoken(?:s|izer|ization|izing)?\s+(?:count|limit|usage|window|budget)\b",
    r"\b(?:count|limit|usage|window|budget)\s+of?\s*tokens?\b",
    r"\btokenizer\b", r"\btokenization\b",
    # A taxonomy is not tax; `\btax\b` already excludes it, but the phrase
    # `tax onomy` appears hyphenated across line breaks in some descriptions.
    r"\btax[- ]?onom(?:y|ies|ic)\b",
    # A digital wallet of loyalty cards is finance; a "wallpaper" is not, and
    # `wallet` must not match inside it.
    r"\bwallpapers?\b",
    # Writing files is filesystem; "write a blog post" is not.
    r"\bwrites? (?:a |an |the )?(?:blog|post|article|essay|summary|report)\b",
    # Prompt/agent "memory" is not personal data by itself.
    r"\bshort[- ]term memory\b", r"\blong[- ]term memory\b",
)

_EXCLUDE = re.compile("|".join(EXCLUSIONS), re.I)
_COMPILED = tuple((cat, re.compile(pat, re.I), why) for cat, pat, why in RULES)


def _text(record):
    name = (record.get("name") or "").replace("-", " ").replace("_", " ")
    return "{} {}".format(name, record.get("description") or "")


def classify(record):
    """Return [{category, matched, why}] for one candidate, possibly empty.

    The matched phrase is the server's own words. It is carried all the way
    into the report so that a category can be disputed by reading, which is
    the only way a classifier like this stays honest at 2,000 records.
    """
    text = _EXCLUDE.sub(" ", _text(record))
    found, seen = [], set()
    for category, pattern, why in _COMPILED:
        hit = pattern.search(text)
        if not hit:
            continue
        key = (category, hit.group(0).lower())
        if category in {c["category"] for c in found} or key in seen:
            continue
        seen.add(key)
        found.append({"category": category,
                      "matched": hit.group(0).strip(),
                      "why": why,
                      "sensitive": category in SENSITIVE})
    return found


def census(records):
    """Population per category, plus what fell through.

    Counts overlap by design: a server can hold several categories, so the
    per-category numbers sum to more than the population. `uncategorised` is
    reported rather than absorbed, because the size of the leftover pile is
    how a reader judges whether the rules cover the ecosystem or just the
    parts that were easy to name.
    """
    per, uncategorised, sensitive = {}, [], set()
    for record in records:
        hits = classify(record)
        if not hits:
            uncategorised.append(record.get("name"))
            continue
        for hit in hits:
            bucket = per.setdefault(hit["category"], {
                "category": hit["category"],
                "sensitive": hit["sensitive"],
                "members": [], "evidence": {}})
            bucket["members"].append(record.get("name"))
            bucket["evidence"].setdefault(hit["matched"].lower(), 0)
            bucket["evidence"][hit["matched"].lower()] += 1
            if hit["sensitive"]:
                sensitive.add(record.get("name"))
    return {
        "population": len(records),
        "categorised": len(records) - len(uncategorised),
        "uncategorised": len(uncategorised),
        "uncategorisedNames": uncategorised[:50],
        "sensitivePopulation": len(sensitive),
        "categories": sorted(per.values(),
                             key=lambda b: -len(b["members"])),
    }


#: (description, categories that must be assigned, categories that must NOT be).
#: Every near-miss here was found in the live corpus, and each one was at some
#: point classified wrongly. A rule that stops working is invisible in a total
#: -- the count simply gets smaller -- so each rule is pinned to a case it has
#: to keep getting right.
WITNESSES = (
    ("CodeScene MCP Server - Code Health analysis for coding agents",
     (), ("health",)),
    ("Service healthcheck and monitoring endpoints", (), ("health",)),
    ("MCP server for querying Apple Health data", ("health",), ()),
    ("Tebra practice management covering patients and appointments",
     ("health",), ()),
    ("Report token count and context window usage", (), ("credentials",)),
    ("A fast tokenizer for embeddings", (), ("credentials",)),
    ("Read secrets from a 1Password vault", ("credentials",), ()),
    ("Query a databank of public images", (), ("finance",)),
    ("Accept Stripe payments and issue invoices", ("finance",), ()),
    ("Build a taxonomy of documents", (), ("finance",)),
    ("Set desktop wallpapers from a gallery", (), ("finance",)),
    ("MCP server for filesystem access", ("filesystem",), ()),
    ("Write a blog post from an outline", (), ("filesystem",)),
    ("Official Postmark MCP server for sending emails", ("messaging",), ()),
    ("Shell command execution MCP server", ("shell-exec",), ()),
    ("MCP server for the Monaco SDK", (), ("finance", "health", "credentials")),
)


def check():
    """Problems with the rules themselves, for the selfcheck gate.

    This exists because a rule can die silently. An exclusion written with an
    escape that the shell ate matched nothing for an entire corpus run, and
    nothing complained: servers simply stopped being excluded and the category
    grew by one. A census whose rules are not themselves tested reports the
    bugs in its rules as facts about the ecosystem.
    """
    problems = []

    for pattern in EXCLUSIONS:
        for char in pattern:
            if ord(char) < 32:
                problems.append(
                    "exclusion {!r} contains a control character, so it was "
                    "written with an escape that something consumed before "
                    "the regex saw it".format(pattern))
                break
    for _cat, pattern, _why in RULES:
        for char in pattern:
            if ord(char) < 32:
                problems.append(
                    "rule {!r} contains a control character".format(pattern))
                break

    for text, must, must_not in WITNESSES:
        got = {hit["category"] for hit in classify({"name": "", "description": text})}
        for category in must:
            if category not in got:
                problems.append("{!r} should be {} and was not"
                                .format(text[:56], category))
        for category in must_not:
            if category in got:
                problems.append("{!r} was filed under {} and must not be"
                                .format(text[:56], category))

    for hit in classify({"name": "", "description": "Accept Stripe payments"}):
        if not (hit.get("matched") or "").strip():
            problems.append("a category was assigned without quoting the "
                            "words that caused it")
    return problems


def select(records, wanted):
    """Candidates in the named categories, for a targeted sweep.

    Sweeping the first N of an alphabetical list answers "what do MCP servers
    do", which no one is asking. Sweeping the servers that handle money answers
    a question someone has before installing one. The selection carries the
    matched phrase with each record so the eventual report can say why each
    server was in scope.
    """
    wanted = {w.strip().lower() for w in wanted if w.strip()}
    if "sensitive" in wanted:
        wanted.discard("sensitive")
        wanted.update(SENSITIVE)
    chosen = []
    for record in records:
        hits = [h for h in classify(record) if h["category"] in wanted]
        if hits:
            picked = dict(record)
            picked["categories"] = [h["category"] for h in hits]
            picked["categoryEvidence"] = [h["matched"] for h in hits]
            chosen.append(picked)
    return chosen


def main():
    argv = sys.argv[1:]
    if argv and argv[0] == "--select":
        # categories.py --select finance,health <candidates.json> <out.json>
        if len(argv) < 4:
            raise SystemExit("usage: categories.py --select "
                             "<cat[,cat]|sensitive> <candidates.json> <out.json>")
        with io.open(argv[2], encoding="utf-8") as fh:
            data = json.load(fh)
        records = data.get("candidates") if isinstance(data, dict) else data
        chosen = select(records, argv[1].split(","))
        with io.open(argv[3], "w", encoding="utf-8", newline="\n") as fh:
            json.dump({"selectedBy": argv[1], "candidates": chosen}, fh,
                      indent=2, ensure_ascii=False)
            fh.write("\n")
        counts = {}
        for record in chosen:
            for category in record["categories"]:
                counts[category] = counts.get(category, 0) + 1
        print("selected {} of {} candidates in {}".format(
            len(chosen), len(records), argv[1]))
        for category, n in sorted(counts.items(), key=lambda kv: -kv[1]):
            print("   {:<14} {}".format(category, n))
        print("wrote {}".format(argv[3]))
        return 0
    if argv and argv[0] == "--check":
        problems = check()
        for problem in problems:
            print("  " + problem)
        print("{} rule(s), {} exclusion(s), {} witness(es): {}".format(
            len(RULES), len(EXCLUSIONS), len(WITNESSES),
            "all hold" if not problems else "{} PROBLEM(S)".format(len(problems))))
        raise SystemExit(1 if problems else 0)
    if not argv:
        raise SystemExit(__doc__)
    with io.open(argv[0], encoding="utf-8") as fh:
        data = json.load(fh)
    records = data.get("candidates") if isinstance(data, dict) else data
    result = census(records)

    print("population        {}".format(result["population"]))
    print("categorised       {}".format(result["categorised"]))
    print("uncategorised     {}   (left alone, not force-fit)"
          .format(result["uncategorised"]))
    print("in a sensitive category  {}".format(result["sensitivePopulation"]))
    print("")
    print("counts overlap: a server may hold more than one category")
    print("")
    for bucket in result["categories"]:
        mark = "*" if bucket["sensitive"] else " "
        top = sorted(bucket["evidence"].items(), key=lambda kv: -kv[1])[:4]
        print("{} {:<14} {:>5}   {}".format(
            mark, bucket["category"], len(bucket["members"]),
            ", ".join("{} x{}".format(t, n) for t, n in top)))
    print("")
    print("* = holds something worth losing")

    if len(argv) > 1:
        with io.open(argv[1], "w", encoding="utf-8", newline="\n") as fh:
            json.dump(result, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        print("\nwrote {}".format(argv[1]))


if __name__ == "__main__":
    main()
