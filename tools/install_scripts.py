"""Which packages run code when you install them, before you import anything.

`npm install` executes whatever the package puts in preinstall, install or
postinstall, as your user, before a line of your own code runs. That is the
supply-chain vector -- it does not need you to import the package, call it, or
give it a credential. You typed a command and it ran.

Two halves, and only one of them needs a sandbox.

STATIC. The registry publishes the manifest, and the manifest says whether
install hooks are declared. That is a fact about a package, checkable by
anyone, requiring nothing to be executed. It is not evidence of wrongdoing --
native modules legitimately compile on install -- but it is the difference
between "this package can run code at install time" and "it cannot", and that
is the population worth watching.

DYNAMIC (tools/package_probe.py, in the sandbox). Install twice, once with
--ignore-scripts and once without, and subtract. What is left is what the
package's own install code did. Same intervene-and-compare as everywhere else
here.

This file is the static half, because it needs no Docker, no credential and no
driver -- and because a count of how many packages in a category CAN run code
at install is worth having before anyone runs any of them.
"""

from __future__ import annotations

import io
import json
import os
import sys
import urllib.request

HOOKS = ("preinstall", "install", "postinstall")

#: Hook bodies that are conventionally harmless. A native module compiling
#: itself is the reason install hooks exist, and counting node-gyp as a risk
#: signal would bury the interesting cases under the ordinary ones.
ORDINARY = ("node-gyp", "prebuild-install", "node-pre-gyp", "prebuildify",
            "install-cpu-features", "electron-builder install-app-deps")


def manifest(name, timeout=20):
    url = "https://registry.npmjs.org/{}/latest".format(name.replace("/", "%2f"))
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "saydo/0.1"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except Exception:
        return None


def install_hooks(meta):
    """Declared install hooks, and whether each is the ordinary compile kind."""
    scripts = (meta or {}).get("scripts") or {}
    found = []
    for hook in HOOKS:
        body = scripts.get(hook)
        if not body:
            continue
        found.append({
            "hook": hook,
            "body": body[:200],
            "ordinary": any(k in body for k in ORDINARY),
        })
    return found


def survey(names, progress=None):
    """Per-package install-hook facts. Unreachable packages are recorded.

    A package the registry would not answer for is `unknown`, never `none`.
    The difference matters: one is a fact about the package and the other is a
    fact about the network, and merging them reports our own timeouts as
    clean packages.
    """
    rows = []
    for i, name in enumerate(names):
        meta = manifest(name)
        if meta is None:
            rows.append({"name": name, "status": "unknown", "hooks": []})
        else:
            hooks = install_hooks(meta)
            rows.append({"name": name,
                         "status": "hooks" if hooks else "none",
                         "hooks": hooks})
        if progress and (i + 1) % 25 == 0:
            progress(i + 1, len(rows))
    return rows


def check():
    """Problems with this module, for the selfcheck gate. [] = good."""
    problems = []

    loud = install_hooks({"scripts": {"postinstall": "node ./scripts/phone.js"}})
    if not loud or loud[0]["ordinary"]:
        problems.append("a postinstall running an arbitrary script was not "
                        "reported, or was written off as an ordinary build")

    compiling = install_hooks({"scripts": {"install": "node-gyp rebuild"}})
    if not compiling or not compiling[0]["ordinary"]:
        problems.append("a native module compiling itself was not marked "
                        "ordinary, which buries the interesting cases under "
                        "the routine ones")

    if install_hooks({"scripts": {"test": "jest", "build": "tsc"}}):
        problems.append("a package with only build and test scripts was "
                        "reported as running code at install")

    if install_hooks(None) or install_hooks({}):
        problems.append("a package with no scripts at all produced hooks")

    rows = survey([])
    if rows:
        problems.append("surveying nothing produced rows")
    return problems


def main():
    argv = sys.argv[1:]
    if argv and argv[0] == "--check":
        found = check()
        for line in found:
            print("  " + line)
        raise SystemExit(1 if found else 0)
    if not argv:
        raise SystemExit(__doc__)

    with io.open(argv[0], encoding="utf-8") as fh:
        data = json.load(fh)
    records = data.get("candidates") if isinstance(data, dict) else data
    npm = [r for r in records if r.get("registry") == "npm"]
    names = [r["name"] for r in npm]

    def tick(done, _total):
        print("   {} of {}".format(done, len(names)), file=sys.stderr)

    rows = survey(names, tick)
    by_name = {r["name"]: r for r in rows}

    hooked = [r for r in rows if r["status"] == "hooks"]
    unusual = [r for r in hooked
               if any(not h["ordinary"] for h in r["hooks"])]
    unknown = [r for r in rows if r["status"] == "unknown"]

    print("npm packages checked      {}".format(len(rows)))
    print("declare an install hook   {}".format(len(hooked)))
    print("  of those, not a build   {}".format(len(unusual)))
    print("registry did not answer   {}   (unknown, never counted clean)"
          .format(len(unknown)))
    print("")
    print("Declaring a hook is not wrongdoing. It is the population that CAN")
    print("run code on `npm install`, before anything is imported or called.")
    print("")
    for row in unusual[:25]:
        for hook in row["hooks"]:
            if not hook["ordinary"]:
                print("  {:<40} {:<12} {}".format(
                    row["name"][:40], hook["hook"], hook["body"][:60]))

    if len(argv) > 1:
        with io.open(argv[1], "w", encoding="utf-8", newline="\n") as fh:
            json.dump({"rows": rows}, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        print("\nwrote {}".format(argv[1]))
    return by_name


if __name__ == "__main__":
    main()
