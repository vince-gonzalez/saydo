"""Find MCP servers to put under SayDo, from the package registries.

Discovery is deliberately programmatic rather than curated. A hand-picked list
of servers is a list of servers someone already trusted, and a corpus built
only from those cannot say anything about the ecosystem -- it can only confirm
that well-regarded packages are well-behaved.

Two sources:

  npm   registry search API, which is clean JSON and covers the larger half of
        the MCP ecosystem
  PyPI  the simple index, filtered by name, then confirmed through the JSON
        API so that only packages exposing a console entry point survive

Nothing here executes anything. Discovery produces a list; running the list
happens in the container, in CI, never on a developer's machine. A package
found this way is by definition untrusted -- that is the point of measuring it
-- and the sandbox is what makes measuring it safe.
"""

from __future__ import annotations

import json
import re
import sys
import urllib.error
import urllib.request

UA = {"User-Agent": "saydo-discovery/0.1 (+https://github.com/vince-gonzalez/saydo)"}

#: Names that look like an MCP server rather than a client, SDK, or framework.
LOOKS_LIKE_SERVER = re.compile(
    r"(^|[-_])mcp([-_]|$)|mcp[-_]?server|server[-_]?mcp", re.I)

#: Things that are emphatically not a server under test.
NOT_A_SERVER = re.compile(
    r"(client|sdk|proxy|gateway|inspector|devtools|cli-?tools|template|"
    r"boilerplate|example|tutorial|awesome)", re.I)


def _get_json(url, timeout=30):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def npm_candidates(pages=8, per_page=250):
    """MCP servers on npm, newest-relevance first."""
    found = {}
    for page in range(pages):
        url = ("https://registry.npmjs.org/-/v1/search"
               "?text=mcp%20server&size={}&from={}".format(
                   per_page, page * per_page))
        try:
            data = _get_json(url)
        except Exception as e:
            print("  npm page {}: {}".format(page, e), file=sys.stderr)
            break
        objects = data.get("objects", [])
        if not objects:
            break
        for obj in objects:
            pkg = obj.get("package", {})
            name = pkg.get("name", "")
            if not LOOKS_LIKE_SERVER.search(name) or NOT_A_SERVER.search(name):
                continue
            found[name] = {
                "registry": "npm",
                "name": name,
                "version": pkg.get("version", ""),
                "description": (pkg.get("description") or "")[:180],
                "links": (pkg.get("links") or {}).get("repository", ""),
            }
    return found


def pypi_candidates(limit=400):
    """MCP servers on PyPI that expose a console entry point.

    The simple index is the only complete listing, so it is filtered by name
    first and then each survivor is confirmed through the JSON API. A package
    with no console script cannot be launched over stdio and is dropped rather
    than recorded as a failure later.
    """
    try:
        req = urllib.request.Request("https://pypi.org/simple/", headers=UA)
        with urllib.request.urlopen(req, timeout=120) as r:
            index = r.read().decode("utf-8", "replace")
    except Exception as e:
        print("  pypi index: {}".format(e), file=sys.stderr)
        return {}

    names = re.findall(r">([^<]+)</a>", index)
    shortlist = [n for n in names
                 if LOOKS_LIKE_SERVER.search(n) and not NOT_A_SERVER.search(n)]
    print("  pypi: {} names match, confirming up to {}".format(
        len(shortlist), limit), file=sys.stderr)

    found = {}
    for name in shortlist[:limit]:
        try:
            data = _get_json("https://pypi.org/pypi/{}/json".format(name), 20)
        except Exception:
            continue
        info = data.get("info", {})
        found[name] = {
            "registry": "pypi",
            "name": name,
            "version": info.get("version", ""),
            "description": (info.get("summary") or "")[:180],
            "links": (info.get("project_urls") or {}).get("Source", "")
                     or info.get("home_page", "") or "",
        }
    return found


def main():
    out_path = sys.argv[1] if len(sys.argv) > 1 else "corpus/candidates.json"
    which = sys.argv[2] if len(sys.argv) > 2 else "both"

    found = {}
    if which in ("both", "npm"):
        print("discovering on npm ...", file=sys.stderr)
        found.update(npm_candidates())
    if which in ("both", "pypi"):
        print("discovering on pypi ...", file=sys.stderr)
        found.update(pypi_candidates())

    rows = sorted(found.values(), key=lambda r: (r["registry"], r["name"]))
    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump({"discovered": len(rows), "candidates": rows}, fh,
                  indent=2, ensure_ascii=False)
        fh.write("\n")

    by_reg = {}
    for r in rows:
        by_reg[r["registry"]] = by_reg.get(r["registry"], 0) + 1
    print("{}: {} candidates {}".format(out_path, len(rows), by_reg))


if __name__ == "__main__":
    main()
