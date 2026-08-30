"""Find MCP servers by what people actually use, not by what registries list.

`discover.py` enumerates the npm registry and the PyPI simple index for
anything whose name or description mentions MCP. That answers "what has been
published", which is not the question. A keyword scrape of a package registry
returns whatever was uploaded, in upload order, with no signal about whether a
single person ever installed it -- and a measurement of that population says
almost nothing about the ecosystem people are exposed to.

This module reads a curated list instead. `punkpeye/awesome-mcp-servers` is
maintained by hand, organised by category, and its entries are servers rather
than "repositories that mention MCP". That distinction is not pedantic: sorting
GitHub by stars for `mcp-server` returns n8n, gemini-cli and private-gpt at the
top, none of which is an MCP server. Whatever a corpus is drawn from, the first
question is what the population actually contains.

The bridge from "listed repository" to "something the harness can run" is the
install command the list entries carry in their own prose -- `npx -y foo`,
`pip install bar`, `uvx baz`. Roughly a sixth of the entries have one. The rest
are recorded as `unrunnable` WITH their reason rather than dropped, because a
corpus that silently discards what it cannot handle reports a coverage rate
that describes the tool instead of the ecosystem.

Nothing here executes anything. It reads a document and produces a candidate
list, and every candidate keeps a pointer to the entry it came from so a reader
can check the provenance of any row.

Usage:
    python discover_github.py corpus/candidates-github.json
    python discover_github.py out.json --stars      # enrich via the GitHub API
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import sys
import time
import urllib.request

#: The curated source. Its own README is the data.
LIST_RAW = ("https://raw.githubusercontent.com/punkpeye/"
            "awesome-mcp-servers/main/README.md")
LIST_REPO = "https://github.com/punkpeye/awesome-mcp-servers"

_ENTRY = re.compile(
    r"^- \[([^\]]+)\]\((https://github\.com/[^)]+)\)(.*)$", re.M)
_HEADING = re.compile(r"^#{2,3} .*?>?([A-Za-z][A-Za-z0-9 &/,'-]+)\s*$", re.M)

#: Install forms that appear in the entries, in the order we prefer them.
#: npx and uvx run a published package without a project, which is exactly the
#: shape the harness wants.
_INSTALL = [
    ("npm", re.compile(r"`npx (?:-y |--yes )*(@?[A-Za-z0-9._/-]+)")),
    ("pypi", re.compile(r"`uvx ([A-Za-z0-9._-]+)")),
    ("pypi", re.compile(r"`pip install (?:-U )?([A-Za-z0-9._-]+)")),
    ("npm", re.compile(r"`npm i(?:nstall)? (?:-g )?(@?[A-Za-z0-9._/-]+)")),
]


def fetch(url=LIST_RAW, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": "saydo-discover"})
    with urllib.request.urlopen(req, timeout=timeout) as fh:
        return fh.read().decode("utf-8", "replace")


def _sections(markdown):
    """(offset -> category) so each entry can be told where it sits."""
    marks = []
    for m in re.finditer(r"^#{2,3} (.+)$", markdown, re.M):
        title = re.sub(r"<[^>]+>", "", m.group(1))
        title = re.sub(r"[^\w &/,'-]", "", title).strip()
        marks.append((m.start(), title))
    return marks


def _category_at(marks, offset):
    found = ""
    for start, title in marks:
        if start > offset:
            break
        found = title
    return found


def parse(markdown):
    """Every listed server, whether or not the harness can run it."""
    marks = _sections(markdown)
    rows = []
    for m in _ENTRY.finditer(markdown):
        repo_name, url, tail = m.group(1), m.group(2), m.group(3)
        # Strip the badge soup so the description is readable prose.
        text = re.sub(r"\[!\[[^\]]*\]\([^)]*\)\]\([^)]*\)", "", tail)
        text = re.sub(r"\s+", " ", text).strip(" -—")
        row = {
            "source": "awesome-mcp-servers",
            "repo": url,
            "repoName": repo_name,
            "category": _category_at(marks, m.start()),
            "description": text[:400],
        }
        for registry, pattern in _INSTALL:
            hit = pattern.search(tail)
            if hit:
                row["registry"] = registry
                row["name"] = hit.group(1)
                row["version"] = ""
                break
        else:
            row["registry"] = "unrunnable"
            row["name"] = repo_name
            # Named, not silently dropped. The share of a curated ecosystem
            # that cannot be launched from its own listing is a finding about
            # that ecosystem, and discarding it would turn a fact about the
            # corpus into a flattering fact about the harness.
            row["reason"] = ("the listing carries no npx/uvx/pip command, so "
                             "there is no way to start it without reading the "
                             "repository by hand")
        rows.append(row)
    return rows


def add_stars(rows, token=None, pause=0.8):
    """Attach star counts. Optional: it costs one API call per repository."""
    token = token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    headers = {"User-Agent": "saydo-discover",
               "Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    for row in rows:
        slug = row["repo"].replace("https://github.com/", "").strip("/")
        if slug.count("/") != 1:
            continue
        try:
            req = urllib.request.Request(
                "https://api.github.com/repos/" + slug, headers=headers)
            with urllib.request.urlopen(req, timeout=20) as fh:
                data = json.load(fh)
            row["stars"] = data.get("stargazers_count")
            row["pushedAt"] = (data.get("pushed_at") or "")[:10]
        except Exception as exc:                     # rate limit, 404, network
            row["starsError"] = "{}: {}".format(type(exc).__name__, exc)[:120]
        time.sleep(pause)
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--stars", action="store_true",
                    help="enrich with star counts (slow; one call per repo)")
    ap.add_argument("--limit", type=int, default=0,
                    help="keep only the first N runnable candidates")
    ap.add_argument("--from-file", help="read the list from disk, not the net")
    args = ap.parse_args()

    markdown = (io.open(args.from_file, encoding="utf-8", errors="replace").read()
                if args.from_file else fetch())
    rows = parse(markdown)
    runnable = [r for r in rows if r["registry"] != "unrunnable"]
    if args.limit:
        runnable = runnable[:args.limit]
    if args.stars:
        add_stars(runnable)

    payload = {
        "source": {"list": LIST_REPO, "raw": LIST_RAW,
                   "note": "a curated list of servers, not a registry keyword "
                           "search; entry count is the list's, not ours"},
        "listed": len(rows),
        "discovered": len(runnable),
        "unrunnable": len(rows) - len([r for r in rows
                                       if r["registry"] != "unrunnable"]),
        "candidates": runnable,
    }
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with io.open(args.out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False, sort_keys=True)
        fh.write("\n")

    by_reg = {}
    for r in runnable:
        by_reg[r["registry"]] = by_reg.get(r["registry"], 0) + 1
    print("{}: {} listed, {} runnable ({})".format(
        args.out, payload["listed"], payload["discovered"],
        ", ".join("{} {}".format(v, k) for k, v in sorted(by_reg.items()))))
    print("{} listed servers cannot be started from their own entry; they are "
          "counted, not hidden.".format(payload["unrunnable"]))


if __name__ == "__main__":
    main()
