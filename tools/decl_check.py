"""Validate WARRANT declarations, and prove the validation can fail.

Checks, per declaration:

  1. The document validates against spec/declaration.schema.json. This needs
     the jsonschema package; if it is missing the check REFUSES rather than
     passing silently -- a validator that skips its main check and says OK is
     the exact failure this project exists to prevent.
  2. Invariant ids are unique.
  3. Every appliesTo entry names a bound tool, or is the single element "*".
  4. A refusal-tool invariant names a bound tool.
  5. status "declared" requires a supplier signature; absent one, only
     "draft" is accepted.
  6. If a capture file is given, every bound digest is recomputed from the
     captured definitions and must match, and the bound tool set must equal
     the captured tool set exactly -- a tool present live but absent from the
     declaration is undeclared surface, and undeclared surface is a finding,
     not a pass.

`selfcheck` mutates a known-good declaration five ways and requires every
mutation to be REJECTED. If any mutation passes, the gate cannot fail, and a
gate that cannot fail proves nothing.

Usage:
    python decl_check.py <schema.json> <declaration.json> [capture.json]
    python decl_check.py selfcheck <schema.json> <declaration.json> <capture.json>
"""

from __future__ import annotations

import copy
import json
import sys

import jcs

try:
    import jsonschema
except ImportError:
    jsonschema = None


def _load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def problems_with(doc, schema, capture=None):
    """Every problem found, as plain sentences. Empty means valid."""
    found = []

    if jsonschema is None:
        return ["REFUSED: the jsonschema package is not available, so the "
                "schema check cannot run. Install it; do not treat this as "
                "a pass."]
    validator = jsonschema.Draft202012Validator(schema)
    for err in sorted(validator.iter_errors(doc), key=str):
        found.append("schema: {}: {}".format(
            "/".join(str(p) for p in err.absolute_path) or "$", err.message))
    if found:
        return found  # structural problems make the rest unreliable

    ids = [inv["id"] for inv in doc["invariants"]]
    for dup in sorted({i for i in ids if ids.count(i) > 1}):
        found.append("invariants: id {!r} appears more than once".format(dup))

    bound = {t["name"] for t in doc["binding"]["tools"]}
    for inv in doc["invariants"]:
        applies = inv["appliesTo"]
        if applies == ["*"]:
            pass
        else:
            for name in applies:
                if name == "*":
                    found.append("invariant {}: '*' must be the only "
                                 "appliesTo entry".format(inv["id"]))
                elif name not in bound:
                    found.append("invariant {}: applies to {!r}, which is "
                                 "not a bound tool".format(inv["id"], name))
        if inv["type"] == "refusal-tool":
            tool = (inv.get("params") or {}).get("tool")
            if tool not in bound:
                found.append("invariant {}: refusal tool {!r} is not a "
                             "bound tool".format(inv["id"], tool))

    if doc["status"] == "declared":
        roles = {s.get("role") for s in doc.get("signatures", [])}
        if "supplier" not in roles:
            found.append("status: 'declared' without a supplier signature; "
                         "an unsigned declaration is a draft")

    if capture is not None:
        live = {t["name"]: t for t in capture["tools"]}
        declared = {t["name"]: t for t in doc["binding"]["tools"]}
        for name in sorted(set(live) - set(declared)):
            found.append("binding: live tool {!r} is not bound; undeclared "
                         "surface is a finding, not a pass".format(name))
        for name in sorted(set(declared) - set(live)):
            found.append("binding: bound tool {!r} is not served "
                         "live".format(name))
        for name in sorted(set(declared) & set(live)):
            recomputed = jcs.digest(live[name]["definition"])
            stated = declared[name]["definitionDigest"]["value"]
            if recomputed != stated:
                found.append("binding: {}: declared digest {} but the "
                             "captured definition hashes to {}".format(
                                 name, stated, recomputed))

    return found


def check_one(schema_path, decl_path, capture_path=None):
    schema = _load(schema_path)
    doc = _load(decl_path)
    capture = _load(capture_path) if capture_path else None
    found = problems_with(doc, schema, capture)
    if found:
        print("{}: REJECTED".format(decl_path))
        for p in found:
            print("  - " + p)
        return 1
    against = " against live capture" if capture else ""
    print("{}: valid {} declaration, {} tools bound, {} invariants{}".format(
        decl_path, doc["status"], len(doc["binding"]["tools"]),
        len(doc["invariants"]), against))
    return 0


def selfcheck(schema_path, decl_path, capture_path):
    """Prove the gate can fail: five mutations, five required rejections."""
    schema = _load(schema_path)
    good = _load(decl_path)
    capture = _load(capture_path)

    if problems_with(good, schema, capture):
        print("selfcheck needs a declaration that passes; this one does not")
        return 1

    def mutate(label, fn):
        doc = copy.deepcopy(good)
        fn(doc)
        found = problems_with(doc, schema, capture)
        verdict = "rejected" if found else "ACCEPTED -- THE GATE IS BROKEN"
        print("  {:<28} {}".format(label, verdict))
        return bool(found)

    def tamper_digest(doc):
        v = doc["binding"]["tools"][0]["definitionDigest"]["value"]
        flipped = ("0" if v[-1] != "0" else "1")
        doc["binding"]["tools"][0]["definitionDigest"]["value"] = v[:-1] + flipped

    print("selfcheck: every mutation below must be rejected")
    results = [
        mutate("tampered tool digest", tamper_digest),
        mutate("unknown invariant type",
               lambda d: d["invariants"][0].update(type="vibes")),
        mutate("applies to unbound tool",
               lambda d: d["invariants"][-1].update(appliesTo=["no_such_tool"])),
        mutate("duplicate invariant id",
               lambda d: d["invariants"][1].update(id=d["invariants"][0]["id"])),
        mutate("declared without signature",
               lambda d: d.update(status="declared")),
    ]
    if all(results):
        print("selfcheck: all 5 mutations rejected; the gate can fail")
        return 0
    print("selfcheck: FAILED -- a mutation was accepted")
    return 1


def main():
    argv = sys.argv[1:]
    if argv and argv[0] == "selfcheck":
        if len(argv) != 4:
            raise SystemExit(__doc__)
        raise SystemExit(selfcheck(argv[1], argv[2], argv[3]))
    if len(argv) not in (2, 3):
        raise SystemExit(__doc__)
    raise SystemExit(check_one(*argv))


if __name__ == "__main__":
    main()
