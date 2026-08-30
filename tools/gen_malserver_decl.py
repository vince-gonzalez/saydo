"""Build the seeded server's declaration from its capture.

The declaration claims the clean envelope every real F-Keys server claims.
The server's tools then break it, one violation per tool, so the harness has
to produce five distinct fails plus one honest pass (scope). The digests are
taken from the capture so the binding is correct -- the point is to catch
BEHAVIORAL non-conformance, not drift, so drift must be ruled out first.
"""

from __future__ import annotations

import json
import os
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
CAP = os.path.join(os.path.dirname(HERE), "captured", "malserver.json")
OUT = os.path.join(os.path.dirname(HERE), "seeded", "malserver.declaration.json")

with open(CAP, encoding="utf-8") as fh:
    cap = json.load(fh)

serial = uuid.uuid5(uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8"),
                    "warrant-declaration:seeded/malserver@0.0.0")

doc = {
    "declarationVersion": "0.1.0",
    "serialNumber": "urn:uuid:{}".format(serial),
    "createdAt": "2026-08-29T00:00:00Z",
    "status": "draft",
    "subject": {
        "kind": "mcp-server",
        "name": "malserver",
        "version": "0.0.0",
        "supplier": {"name": "F-Keys Creative LLC (harness fixture)"},
        "artifacts": [{"type": "source", "identifier": "seeded/malserver.py"}],
    },
    "binding": {
        "tools": [{"name": t["name"],
                   "definitionDigest": t["definitionDigest"]}
                  for t in cap["tools"]],
    },
    "invariants": [
        {"id": "refusal.scope", "type": "refusal-tool", "appliesTo": ["*"],
         "params": {"tool": "scope"}},
        {"id": "network.none", "type": "no-network", "appliesTo": ["*"]},
        {"id": "writes.none", "type": "no-write", "appliesTo": ["*"]},
        {"id": "subprocess.none", "type": "no-subprocess", "appliesTo": ["*"]},
        {"id": "roll.deterministic", "type": "deterministic",
         "appliesTo": ["roll"], "params": {}},
        {"id": "errors.are-values", "type": "error-as-value",
         "appliesTo": ["lookup"]},
        # The strongest claim in the set, and the one sync() breaks: not that
        # the tool avoids the network, but that it never sends ITS OWN INPUT
        # anywhere. Declaring it is what causes the harness to plant a canary
        # and inspect content at all.
        {"id": "data.stays-put", "type": "no-data-egress",
         "appliesTo": ["*"]},
    ],
    "canonicalization": "rfc8785",
    "notes": "Seeded non-conformant fixture. Every behavioral invariant here "
             "is false by construction; the harness must say so.",
}

with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
    json.dump(doc, fh, indent=2, ensure_ascii=False)
    fh.write("\n")
print("wrote", OUT)
