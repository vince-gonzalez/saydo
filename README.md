# warrant (name provisional)

A tool declares, in a signed machine-readable contract, exactly what it does.
A harness proves the tool obeys the contract. Every run emits a hash-chained
receipt an auditor verifies without trusting anybody.

Working repository. Nothing here is published, and nothing here is a claim of
conformance: every declaration currently carries `status: "draft"`.

## Layout

    spec/declaration.schema.json   the behavioral declaration, JSON Schema 2020-12
    spec/DECLARATION-DRAFT.md      field semantics and invariant types (draft)
    captured/                      live tools/list of the five released F-Keys
                                   MCP servers, with RFC 8785 definition digests
    declarations/                  draft declarations for the five servers
    tools/jcs.py                   RFC 8785 canonicalization (restricted subset;
                                   refuses what it cannot vouch for)
    tools/capture_tools.py         speaks MCP over stdio, digests tools/list
    tools/gen_declarations.py      builds the five declarations from captures
    tools/decl_check.py            validates declarations; `selfcheck` proves
                                   the validation can fail

## Reproduce

Install the five released packages (`authorecon==1.1.0`, `certivl==0.2.0`,
`loadbearing==0.2.0`, `mmforge==0.2.0`, `remapwrap==0.6.0`, each with the
`[mcp]` extra) and `jsonschema` into a throwaway environment, then:

    python tools/capture_tools.py captured/certivl.json -- certivl-mcp
    python tools/gen_declarations.py captured declarations
    python tools/decl_check.py spec/declaration.schema.json declarations/certivl.declaration.json captured/certivl.json
    python tools/decl_check.py selfcheck spec/declaration.schema.json declarations/certivl.declaration.json captured/certivl.json

Digests bind to the released PyPI artifacts, not to any working tree.

## Prior art this builds on

- TBOM v1.0.2, Jason M. Lovell, 2026 — 10.5281/zenodo.18459260
- CTMS 1.0, George Kanellopoulos, 2026 — github.com/gkanellopoulos/ctms

Both are provenance: they establish that tool metadata is what the publisher
released, and both state that verifying behavior against the metadata is out
of their scope. That out-of-scope line is what this repository is for.
