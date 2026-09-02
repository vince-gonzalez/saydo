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
    if not os.path.isdir(folder):
        print("no batch directory at {!r}: every sweep job failed or uploaded "
              "nothing, so there is no corpus to report on".format(folder))
        return results, batches
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

    # Checked again here, not only in the sweep. A batch installs many
    # packages into one image, so a generic binary name is answered by
    # whichever package won PATH, and the sweep then files one server's
    # behaviour under several projects' names. Batches produced before that
    # check existed are merged by this function, and re-deriving a report from
    # them would republish the misattribution. This is the last point where
    # every record is in one place.
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import sweep_scale
    disowned = sweep_scale.disown_collisions(results)
    if disowned:
        print("disowned {} record(s): another package in the same batch "
              "produced an identical capture, so which one ran cannot be "
              "established".format(len(disowned)))
        for name, twins in disowned:
            print("   {:<44} one of {}".format(name[:44], len(twins) + 1))
    return results, batches


def tally(results):
    t = {"discovered": len(results), "measured": 0, "unstartable": 0,
         "image_unavailable": 0, "errored": 0, "harness_refused": 0,
         "ambiguous": 0}
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
        elif outcome == "ambiguous-launch":
            # Its own row. These ran and produced real behaviour; what is
            # missing is which package it belonged to. Counting them as
            # errors would hide the reason -- the reader would see six
            # failures and never learn that the sweep could not tell whose
            # code it had measured.
            t["ambiguous"] += 1
        else:
            t["errored"] += 1
    return t


def data_flow_summary(results):
    """Which servers carry their input out, and to where.

    `silent` is the category that matters most and is easiest to misreport: a
    server that started, listed its tools, and then did nothing observable at
    all. Counting those as "not exfiltrating" would turn "we never got it to
    act" into a clean bill of health, which is the single most dishonest thing
    this report could do.
    """
    exfiltrating, telemetry_only, unexamined, silent = [], [], [], []
    destinations = {}
    for r in results:
        if r.get("outcome") != "measured":
            continue
        flow = r.get("dataFlow") or {}
        # ONE definition of silent for the whole table, and it is the one
        # every record can answer: no observed data flow.
        #
        # `established == 0` is the better signal -- it is the harness's own
        # judgement that nothing happened -- but it was added to the sweep
        # part-way through a run, so the early batches do not carry it. Using
        # it where present and falling back where absent would compute the
        # headline number two different ways within one corpus, which is a
        # table assembled from two experiments wearing one label. It is
        # reported separately below, with its own denominator, instead.
        if not flow:
            silent.append(r["name"])
            continue
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
    return exfiltrating, telemetry_only, unexamined, destinations, silent


def write_report(results, batches, out_md):
    t = tally(results)
    exfil, telemetry, unexamined, destinations, silent = \
        data_flow_summary(results)
    measured = t["measured"]
    acted = measured - len(silent)

    L = []
    W = L.append
    # The title has to survive the body. An earlier one promised "what MCP
    # tools actually do with your data", and four paragraphs later the report
    # says it established nothing of the kind -- a headline the evidence
    # withdraws is a false claim no matter how carefully the text under it
    # hedges, and it is the line most people will read alone.
    W("# How hard is it to audit an MCP server from the outside?\n")
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
    W("| ran, but could not be attributed | {} |".format(t["ambiguous"]))
    W("| errored | {} |".format(t["errored"]))
    W("")
    if t["ambiguous"]:
        W("The attribution row is a limit of the method, not of the servers. "
          "A batch installs many packages into one image, and several publish "
          "a binary under the same generic name, so one server can answer for "
          "another. Those runs produced real behaviour that cannot be tied to "
          "a named package, and nothing observed in them is attributed to "
          "any. Earlier sweeps recorded such runs under whichever package was "
          "asked for, which credited projects with behaviour that was not "
          "theirs.\n")
    imported = [r for r in results
                if (r.get("importProbe") or {}).get("imported")]
    acted_on_import = [r for r in imported
                       if (r["importProbe"].get("network")
                           or r["importProbe"].get("subprocess"))]
    if imported:
        W("## What happens on import alone\n")
        W("Separate from anything above. Importing a package runs its module "
          "body -- no server, no tools, no credential -- and it is what every "
          "user of that package does. A package that would not start as a "
          "server is still installed and still imports, so this covers the "
          "servers the rest of the report could say nothing about.\n")
        W("| | packages |")
        W("|---|---|")
        W("| imported successfully | {} |".format(len(imported)))
        W("| reached the network or spawned a process on import | {} |"
          .format(len(acted_on_import)))
        W("")
        W("Run with no network at all, so nothing was reached. What is "
          "recorded is what the package TRIED to do at import, which the "
          "monitor sees when the call is made.\n")

    W("Only the first row supports any claim about behaviour. Most MCP "
      "servers require a credential, and one that declined to run without a "
      "credential has not been shown to be safe -- it has not been shown "
      "anything. Every rate below is over the {} exercised servers, not the "
      "{} discovered ones.\n".format(measured, t["discovered"]))

    W("Of the {} that started, **{} did nothing observable**: they listed "
      "their tools and then made no network call the harness could see, "
      "because a tool invoked with placeholder arguments and no credential "
      "usually rejects the call before it does any work. Those servers have "
      "NOT been shown to be well behaved. Nothing was established about them "
      "in either direction, and they are excluded from every rate below "
      "rather than counted as clean.\n".format(measured, len(silent)))

    # The harness's own coverage judgement, reported beside the figure above
    # rather than folded into it. `established` counts invariants about a
    # server's CONDUCT that were demonstrated, so zero means the run showed
    # nothing whatever else it emitted. It is the better measure of silence.
    # It is kept separate because it was added to the sweep mid-run, so it is
    # available for only part of the corpus, and a headline computed one way
    # for some rows and another way for the rest is a table built from two
    # experiments. The denominator is stated so the reader can weigh it.
    scored = [r for r in results
              if r.get("outcome") == "measured" and r.get("established") is not None]
    if scored:
        nothing = [r for r in scored if r["established"] == 0]
        W("A second, stricter reading, available for {} of the {} exercised "
          "servers: {} of those {} established NOTHING -- no invariant about "
          "the server's conduct was demonstrated, whatever traffic it did or "
          "did not emit. This figure is reported separately rather than merged "
          "with the one above, because the two are not the same test and "
          "combining them would describe a corpus that was never measured "
          "uniformly.\n".format(len(scored), measured, len(nothing),
                                len(scored)))

    if not measured:
        W("No server was exercised, so this run supports no behavioural "
          "claim at all.\n")
    elif not acted:
        W("## The finding is about auditability, not about safety\n")
        W("Not one server that started could be made to act. This run "
          "therefore says nothing about whether any of them exfiltrate data, "
          "and it would be dishonest to present it as though it did.\n")
        W("It does say something worth saying: **an MCP server is very hard "
          "to audit from the outside.** Behaviour appears only when a tool is "
          "given credentials and inputs it accepts, which an auditor examining "
          "someone else's server does not have. That is precisely the argument "
          "for the author DECLARING what a tool does, and for conformance "
          "being checked where the credentials already are - in the "
          "publisher's own CI - rather than guessed at from outside.\n")
    else:
        W("## The finding\n")
        W("Of the {} servers that actually did something, **{} sent the "
          "tool's own input to a remote host**, {} contacted a host without "
          "carrying the input, and {} sent payloads that could not be "
          "decoded.\n".format(acted, len(exfil), len(telemetry),
                              len(unexamined)))
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

    diag = {}
    for r in results:
        d = r.get("diagnosis")
        if d:
            diag[d["class"]] = diag.get(d["class"], 0) + 1
    if diag:
        W("## Why the rest would not start\n")
        W("| reason | servers |")
        W("|---|---|")
        labels = {
            "needs-configuration": "demanded a key, token or setting",
            "crashes": "started and crashed",
            "hangs": "started and never answered",
            "wrong-command": "SayDo guessed the launch command wrongly",
            "sandbox-denied": "SayDo's sandbox refused a write it needed to "
                              "start",
            "silent": "exited quietly, saying nothing",
            "no-command": "no launch command could be derived",
            "unknown": "could not be classified",
        }
        ours = ("wrong-command", "sandbox-denied")
        for k, n in sorted(diag.items(), key=lambda kv: -kv[1]):
            W("| {}{} | {} |".format(labels.get(k, k),
                                     " **(SayDo's fault)**" if k in ours else "",
                                     n))
        W("")
        mine = sum(diag.get(k, 0) for k in ours)
        if mine:
            W("{} of these are SayDo's fault, not the ecosystem's, and are "
              "marked as such rather than buried so the number above them can "
              "be read for what it is. A harness that breaks a server and then "
              "files it under the server's failures is not measuring "
              "anything.\n".format(mine))
        if diag.get("sandbox-denied"):
            W("`sandbox-denied` in particular is the containment refusing a "
              "write the server makes before it can serve at all, usually a "
              "state directory under its own home. It says nothing whatsoever "
              "about the server; it is the reason the sandbox now provides an "
              "ephemeral writable home, and those writes are still measured "
              "against the declared scope once the server survives long enough "
              "to be judged.\n")
        W("A server demanding configuration is the single most common reason "
          "an MCP server cannot be audited by anyone who does not already "
          "operate it. That is the argument for the author declaring what "
          "their tool does and proving it where the credentials already "
          "are.\n")

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
