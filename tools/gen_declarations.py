"""Generate the five F-Keys draft declarations from captured tool definitions.

The tool digests come from captured/<name>.json, which capture_tools.py took
from the RELEASED PyPI artifacts, not from a working tree. The invariants are
authored here, one table per server, and each entry states only what the
released source establishes:

  - certivl computes; it touches nothing. Its two property invariants are the
    reason the package exists.
  - loadbearing and mmforge read the one file they are pointed at and nothing
    else, and answer deterministically from it.
  - authorecon is the honest hard case. Its reference-resolution tools follow
    the record wherever it points -- a DOI resolves to whatever host the
    publisher uses this year, by design -- so NO egress bound is declared for
    check_references beyond its API set, none at all for lint_deposit, and
    the absence is stated instead of papered over. An egress allowlist that
    the tool is designed to exceed would be a false declaration.
  - remapwrap has the one tool that changes a machine. save_board gets a
    write-scope bound to the profiles folder and a property: a layout that
    fails validation is never written.

Every declaration is emitted with status "draft". A draft is a claim sheet,
not a warrant: nothing here is warranted until the conformance harness has
demonstrated each invariant against the bound artifact and the supplier has
signed the result.

Usage:
    python gen_declarations.py <captured_dir> <output_dir>
"""

from __future__ import annotations

import json
import os
import sys
import uuid

SUPPLIER = {"name": "F-Keys Creative LLC", "url": "https://www.f-keys.com"}

# Fixed per (name, version) so regeneration is reproducible: the serial is
# uuid5 over the subject, not a random draw.
_NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # RFC 4122 DNS

OPENALEX_ORCID = ["api.openalex.org", "pub.orcid.org"]

SERVERS = {
    "authorecon": {
        "version": "1.1.0",
        "purl": "pkg:pypi/authorecon@1.1.0",
        "repository": "https://github.com/vince-gonzalez/apriori",
        "invariants": [
            {"id": "refusal.scope", "type": "refusal-tool",
             "appliesTo": ["*"], "params": {"tool": "scope"}},
            {"id": "scope.offline", "type": "no-network",
             "appliesTo": ["scope"]},
            {"id": "scan.offline", "type": "no-network",
             "appliesTo": ["scan_document"],
             "note": "The document scan is local. Nothing read from the "
                     "document leaves the machine."},
            {"id": "scan.reads-its-argument", "type": "read-scope",
             "appliesTo": ["scan_document"], "params": {"pathArgs": ["path"]}},
            {"id": "writes.none", "type": "no-write", "appliesTo": ["*"]},
            {"id": "subprocess.none", "type": "no-subprocess",
             "appliesTo": ["*"]},
            {"id": "egress.reference-apis", "type": "network-allowlist",
             "appliesTo": ["check_references"],
             "params": {"hosts": ["api.crossref.org", "api.datacite.org",
                                  "api.openalex.org",
                                  "eutils.ncbi.nlm.nih.gov",
                                  "openlibrary.org", "www.ebi.ac.uk"]}},
            {"id": "egress.record-apis", "type": "network-allowlist",
             "appliesTo": ["check_retractions", "check_venues",
                           "check_self_citation"],
             "params": {"hosts": OPENALEX_ORCID}},
        ],
        "notes": (
            "No egress bound is declared for lint_deposit: its host set has "
            "not been established from the released source, and a bound that "
            "might be exceeded is worse than none. The link-checking paths in "
            "this package follow DOIs to whatever host currently serves the "
            "work; that is what a DOI is for, and it is why no server-wide "
            "allowlist appears here. No error-as-value invariant is declared: "
            "several tools let exceptions reach the transport."
        ),
    },
    "certivl": {
        "version": "0.2.0",
        "purl": "pkg:pypi/certivl@0.2.0",
        "repository": "https://github.com/vince-gonzalez/certivl",
        "invariants": [
            {"id": "refusal.scope", "type": "refusal-tool",
             "appliesTo": ["*"], "params": {"tool": "scope"}},
            {"id": "network.none", "type": "no-network", "appliesTo": ["*"]},
            {"id": "writes.none", "type": "no-write", "appliesTo": ["*"]},
            {"id": "reads.none", "type": "read-scope", "appliesTo": ["*"],
             "params": {"pathArgs": []},
             "note": "Evaluation is arithmetic over the request. No file "
                     "is opened."},
            {"id": "subprocess.none", "type": "no-subprocess",
             "appliesTo": ["*"]},
            {"id": "answers.deterministic", "type": "deterministic",
             "appliesTo": ["*"], "params": {}},
            {"id": "errors.are-values", "type": "error-as-value",
             "appliesTo": ["*"],
             "note": "An expression outside the language is refused in the "
                     "result payload, not by crashing the transport."},
            {"id": "undecided.on-overlap", "type": "property",
             "appliesTo": ["decide"],
             "params": {"check": "certivl.undecided-on-overlap",
                        "statement": "When the two enclosures overlap and are "
                                     "not both exact and equal, the verdict "
                                     "is UNDECIDED. The side the midpoint "
                                     "fell on is never reported."}},
            {"id": "decimal.read-exactly", "type": "property",
             "appliesTo": ["decide", "enclose"],
             "params": {"check": "certivl.decimal-literal-exact",
                        "statement": "A decimal literal denotes the decimal "
                                     "it spells: 0.1 + 0.2 == 0.3 decides "
                                     "TRUE."}},
        ],
    },
    "loadbearing": {
        "version": "0.2.0",
        "purl": "pkg:pypi/loadbearing@0.2.0",
        "repository": "https://github.com/vince-gonzalez/loadbearing",
        "invariants": [
            {"id": "refusal.scope", "type": "refusal-tool",
             "appliesTo": ["*"], "params": {"tool": "scope"}},
            {"id": "network.none", "type": "no-network", "appliesTo": ["*"]},
            {"id": "writes.none", "type": "no-write", "appliesTo": ["*"]},
            {"id": "scope.reads-nothing", "type": "read-scope",
             "appliesTo": ["scope"], "params": {"pathArgs": []}},
            {"id": "measures.read-the-database", "type": "read-scope",
             "appliesTo": ["measure_severing", "measure_with_witness"],
             "params": {"pathArgs": ["database_path"]},
             "note": "A measurement reads the named database and nothing "
                     "else of the user's."},
            {"id": "subprocess.none", "type": "no-subprocess",
             "appliesTo": ["*"]},
            {"id": "severing.deterministic", "type": "deterministic",
             "appliesTo": ["scope", "measure_severing"],
             "params": {"pathArgs": ["database_path"]},
             "note": "Same database bytes, same targets, same parameters: "
                     "same answer. measure_with_witness is excluded until "
                     "the witness's environment block is classified as "
                     "volatile or not."},
            {"id": "errors.are-values", "type": "error-as-value",
             "appliesTo": ["measure_severing", "measure_with_witness"]},
        ],
    },
    "mmforge": {
        "version": "0.2.0",
        "purl": "pkg:pypi/mmforge@0.2.0",
        "repository": "https://github.com/vince-gonzalez/mmforge",
        "invariants": [
            {"id": "refusal.scope", "type": "refusal-tool",
             "appliesTo": ["*"], "params": {"tool": "scope"}},
            {"id": "network.none", "type": "no-network", "appliesTo": ["*"]},
            {"id": "writes.none", "type": "no-write", "appliesTo": ["*"]},
            {"id": "scope.reads-nothing", "type": "read-scope",
             "appliesTo": ["scope"], "params": {"pathArgs": []}},
            {"id": "analyses.read-the-database", "type": "read-scope",
             "appliesTo": ["analyse_necessity", "census_guards"],
             "params": {"pathArgs": ["database_path"]}},
            {"id": "subprocess.none", "type": "no-subprocess",
             "appliesTo": ["*"]},
            {"id": "analysis.deterministic", "type": "deterministic",
             "appliesTo": ["scope", "analyse_necessity", "census_guards"],
             "params": {"pathArgs": ["database_path"]}},
            {"id": "errors.are-values", "type": "error-as-value",
             "appliesTo": ["analyse_necessity", "census_guards"]},
        ],
    },
    "remapwrap": {
        "version": "0.6.0",
        "purl": "pkg:pypi/remapwrap@0.6.0",
        "repository": "https://github.com/vince-gonzalez/f-keys",
        "invariants": [
            {"id": "refusal.scope", "type": "refusal-tool",
             "appliesTo": ["*"], "params": {"tool": "scope"}},
            {"id": "network.none", "type": "no-network", "appliesTo": ["*"]},
            {"id": "subprocess.none", "type": "no-subprocess",
             "appliesTo": ["*"]},
            {"id": "writes.none-except-save", "type": "no-write",
             "appliesTo": ["scope", "check_layout", "build_board",
                           "build_soundboard", "build_mixer"]},
            {"id": "save.writes-profiles-only", "type": "write-scope",
             "appliesTo": ["save_board"],
             "params": {"paths": ["${APPDATA}/RemapWrap/profiles"]},
             "note": "The one tool that changes a machine, and the one place "
                     "it is permitted to."},
            {"id": "soundboard.reads-its-folder", "type": "read-scope",
             "appliesTo": ["build_soundboard"], "params": {"pathArgs": ["folder"]}},
            {"id": "builders.read-nothing", "type": "read-scope",
             "appliesTo": ["scope", "check_layout", "build_board",
                           "build_mixer", "save_board"],
             "params": {"pathArgs": [],
                        "alsoAllowed": ["${APPDATA}/RemapWrap/profiles"]}},
            {"id": "builders.deterministic", "type": "deterministic",
             "appliesTo": ["check_layout", "build_board", "build_mixer"],
             "params": {"volatile": ["id"]},
             "note": "The functional layout is deterministic. Control 'id' "
                     "fields are opaque and allocated from a process counter, "
                     "so they vary with call history and are excluded. This "
                     "is a genuine dogfood finding: the builders' output "
                     "carries process state in those ids; harmless to a "
                     "board's function, but it is why the claim is scoped."},
            {"id": "errors.are-values", "type": "error-as-value",
             "appliesTo": ["*"]},
            {"id": "save.refuses-broken-layouts", "type": "property",
             "appliesTo": ["save_board"],
             "params": {"check": "remapwrap.refuse-invalid-write",
                        "statement": "A layout that fails validation is "
                                     "never written. The result says "
                                     "written: false and no file appears."}},
        ],
        "notes": (
            "save_board also detects the Microsoft Store app-container "
            "redirection and reports written: false rather than a false "
            "success. That behavior is only observable inside a sandboxed "
            "interpreter, so it is recorded here and not declared as an "
            "invariant the ordinary harness environment can demonstrate."
        ),
    },
}


def build(name, table, captured):
    subject = {
        "kind": "mcp-server",
        "name": name,
        "version": table["version"],
        "supplier": SUPPLIER,
        "repository": {"url": table["repository"]},
        "artifacts": [{"type": "pypi", "identifier": table["purl"]}],
    }
    serial = uuid.uuid5(_NAMESPACE, "warrant-declaration:" + table["purl"])
    doc = {
        "declarationVersion": "0.1.0",
        "serialNumber": "urn:uuid:{}".format(serial),
        "createdAt": "2026-08-29T00:00:00Z",
        "status": "draft",
        "subject": subject,
        "binding": {
            "tools": [{"name": t["name"],
                       "definitionDigest": t["definitionDigest"]}
                      for t in captured["tools"]],
        },
        "invariants": table["invariants"],
        "canonicalization": "rfc8785",
    }
    if "notes" in table:
        doc["notes"] = table["notes"]
    return doc


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    captured_dir, out_dir = sys.argv[1], sys.argv[2]
    os.makedirs(out_dir, exist_ok=True)
    for name, table in sorted(SERVERS.items()):
        with open(os.path.join(captured_dir, name + ".json"),
                  encoding="utf-8") as fh:
            captured = json.load(fh)
        got = captured["server"]["version"]
        if got != table["version"]:
            raise SystemExit(
                "{}: capture is of version {} but the table declares {}. "
                "Recapture from the released artifact before generating."
                .format(name, got, table["version"]))
        doc = build(name, table, captured)
        path = os.path.join(out_dir, name + ".declaration.json")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(doc, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        print("{}: {} tools bound, {} invariants, status {}".format(
            path, len(doc["binding"]["tools"]), len(doc["invariants"]),
            doc["status"]))


if __name__ == "__main__":
    main()
