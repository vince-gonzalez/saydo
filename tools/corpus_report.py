"""Merge sweep batches into one corpus and write the findings up honestly.

The temptation with a corpus this size is to lead with the biggest number. The
number that matters is smaller and harder: of the servers that could actually
be exercised, how many send the tool's own input somewhere, and where.

Three rules shape this report, and they cost headline size on purpose:

  A server that could not be started or exercised is counted separately and
  never folded into a clean total. Most MCP servers need a credential, and a
  server that refused to run without one has not been shown to be safe -- it
  has not been shown anything.

  Rates are quoted over the EXERCISED population, never over the discovered
  one, and both denominators are printed so a reader can check the arithmetic
  rather than take it on faith.

  An opaque payload is reported as unexamined. It never counts toward clean.
"""

from __future__ import annotations

import io
import json
import os
import sys


def load_batches(folder):
    results, batches = [], 0
    for name in sorted(os.listdir(folder)):
        if not name.endswith(".json"):
            continue
        try:
            with io.open(os.path.join(folder, name), encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception:
            continue
        results.extend(data.get("results", []))
        batches += 1
    return results, batches


def tally(results):
    t = {"discovered": len(results), "measured": 0, "unstartable": 0,
         "image_unavailable": 0, "errored": 0, "harness_refused": 0}
    for r in results:
        outcome = r.get("outcome")
        if outcome == "measured":
            t["measured"] += 1
        elif outcome == "unstartable":
            t["unstartable"] += 1
        elif outcome == "image-unavailable":
            t["image_unavailable"] += 1
        elif outcome == "harness-refused":
            t["harness_refused"] += 1
        else:
            t["errored"] += 1
    return t


def data_flow_summary(results):
    """Which servers carry their input out, and to where."""
    exfiltrating, telemetry_only, unexamined = [], [], []
    destinations = {}
    for r in results:
        if r.get("outcome") != "measured":
            continue
        flow = r.get("dataFlow") or {}
        carries = [h for h, v in flow.items()
                   if v.get("relation") in ("input-dependent",
                                            "retained-across-runs")]
        opaque = [h for h, v in flow.items()
                  if v.get("relation") == "unexamined"]
        fixed = [h for h, v in flow.items()
                 if v.get("relation") == "input-independent"]
        for h in carries:
            destinations[h] = destinations.get(h, 0) + 1
        if carries:
            exfiltrating.append((r["name"], carries))
        elif opaque:
            unexamined.append((r["name"], opaque))
        elif fixed:
            telemetry_only.append((r["name"], fixed))
    return exfiltrating, telemetry_only, unexamined, destinations


def write_report(results, batches, out_md):
    t = tally(results)
    exfil, telemetry, unexamined, destinations = data_flow_summary(results)
    measured = t["measured"]

    L = []
    W = L.append
    W("# What MCP tools actually do with your data\n")
    W("DRAFT. Wording is a placeholder pending the author's pass.\n")
    W("A behavioural sweep of {} MCP servers discovered from public package "
      "registries, executed inside a sandbox with no route out except a "
      "recording proxy. Every finding is something the harness OBSERVED.\n"
      .format(t["discovered"]))

    W("## What was actually measured\n")
    W("| outcome | servers |")
    W("|---|---|")
    W("| exercised successfully | {} |".format(measured))
    W("| would not start | {} |".format(t["unstartable"]))
    W("| could not be installed | {} |".format(t["image_unavailable"]))
    W("| harness refused | {} |".format(t["harness_refused"]))
    W("| errored | {} |".format(t["errored"]))
    W("")
    W("Only the first row supports any claim about behaviour. Most MCP "
      "servers require a credential, and one that declined to run without a "
      "credential has not been shown to be safe -- it has not been shown "
      "anything. Every rate below is over the {} exercised servers, not the "
      "{} discovered ones.\n".format(measured, t["discovered"]))

    if not measured:
        W("No server was exercised, so this run supports no behavioural "
          "claim at all.\n")
    else:
        W("## The finding\n")
        W("Of {} servers exercised, **{} sent the tool's own input to a "
          "remote host**, {} contacted a host without carrying the input, and "
          "{} sent payloads that could not be decoded.\n".format(
              measured, len(exfil), len(telemetry), len(unexamined)))
        W("That distinction is the point. A tool contacting a server and a "
          "tool shipping your data look identical on the wire: same host, "
          "same shape, every call. They are told apart by running each server "
          "twice with a different marker planted in its input and seeing "
          "which marker comes out. Watching traffic cannot establish it; "
          "changing the input can.\n")

        if exfil:
            W("### Servers whose egress carried the input\n")
            for name, hosts in sorted(exfil)[:40]:
                W("- `{}` -> {}".format(name, ", ".join(sorted(hosts)[:4])))
            W("")
        if destinations:
            W("### Where the data went\n")
            for host, n in sorted(destinations.items(), key=lambda kv: -kv[1])[:20]:
                W("- `{}` received input from {} server(s)".format(host, n))
            W("")
        if unexamined:
            W("### Not established either way\n")
            W("These sent payloads the harness could not decode. That is not "
              "evidence of good behaviour and is not counted as clean.\n")
            for name, hosts in sorted(unexamined)[:20]:
                W("- `{}` -> {}".format(name, ", ".join(sorted(hosts)[:4])))
            W("")

    W("## How to argue with this\n")
    W("- Servers were run without credentials, so a credentialed server may "
      "do more than is recorded here. Every figure is a lower bound.\n"
      "- Each server was exercised with benign placeholder arguments, not a "
      "real workload.\n"
      "- TLS inspection is cooperative: a tool that pins its certificates "
      "refuses examination, and is reported as unexamined rather than clean.\n"
      "- The corpus is what public registries advertise, which is not the "
      "same as what people actually install.\n"
      "- Every measurement is reproducible: the harness, the declarations and "
      "the receipts are in this repository.\n")
    W("Merged from {} batch file(s).\n".format(batches))

    with io.open(out_md, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(L) + "\n")
    return t, len(exfil)


def main():
    if len(sys.argv) != 4:
        raise SystemExit(
            "usage: corpus_report.py <batch_dir> <out.json> <out.md>")
    folder, out_json, out_md = sys.argv[1], sys.argv[2], sys.argv[3]
    results, batches = load_batches(folder)
    os.makedirs(os.path.dirname(out_json) or ".", exist_ok=True)
    with io.open(out_json, "w", encoding="utf-8", newline="\n") as fh:
        json.dump({"servers": len(results), "results": results}, fh, indent=2,
                  ensure_ascii=False)
        fh.write("\n")
    t, exfil = write_report(results, batches, out_md)
    print("corpus: {} servers, {} exercised, {} carried input out"
          .format(t["discovered"], t["measured"], exfil))


if __name__ == "__main__":
    main()
