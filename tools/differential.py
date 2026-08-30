"""Separate egress that CARRIES the input from egress that merely happens.

A firewall watches the wire. It can see that a tool contacted a host, and with
a honeytoken it can see that some known secret left. What it cannot do is tell
these two apart:

    the tool phones home every time, regardless of what you gave it
    the tool sends whatever you gave it, wherever it likes

Both look identical from the outside: a connection to the same host, every
time. The distinction is causal, and causal questions cannot be answered by
observation alone -- only by intervention. You have to change the input and
see whether the output changes with it.

SayDo can do that because it controls the input. The harness runs the tool
twice with a DIFFERENT canary planted each time, then asks which canary came
out:

    canary A leaves in run A, canary B leaves in run B
        -> the egress carries the input. This is exfiltration, and the
           receipt can say so about THIS tool's data flow, not just its
           network activity.

    the same host is contacted in both runs, no canary in either
        -> the egress is independent of the input. That is telemetry or a
           fixed backend: worth declaring, not worth alarming about.

    a canary from run A appears in run B
        -> the tool RETAINED input across runs. Worse than either case above,
           and invisible to a single-run test.

This is the same move as severing a node to see whether a result still holds:
reach is not responsibility, and contact is not exfiltration. Watching cannot
establish it; intervening can.
"""

from __future__ import annotations

#: How a host's egress relates to the tool's input.
INPUT_DEPENDENT = "input-dependent"
INPUT_INDEPENDENT = "input-independent"
RETAINED = "retained-across-runs"
UNEXAMINED = "unexamined"


def classify(runs):
    """Classify each destination from two or more instrumented runs.

    `runs` is a list of dicts, one per run:
        {"canary": <marker planted in this run>,
         "events": [proxy/monitor events from this run]}

    Returns {host: {"relation", "why", "carried"}}.
    """
    planted = [r["canary"] for r in runs]
    seen = {}

    for index, run in enumerate(runs):
        own = run["canary"]
        for ev in run["events"]:
            name = ev.get("event", "")
            host = ev.get("host")
            if not host or not name.startswith("exfil."):
                continue
            entry = seen.setdefault(host, {"contacted": set(), "carried": [],
                                           "foreign": [], "opaque": 0})
            entry["contacted"].add(index)
            if name == "exfil.match":
                got = ev.get("canary")
                if got == own:
                    entry["carried"].append(index)
                elif got in planted:
                    # A marker from a DIFFERENT run: the tool kept input it
                    # was given earlier and sent it later.
                    entry["foreign"].append((index, got))
            elif name == "exfil.unexamined":
                entry["opaque"] += 1

    out = {}
    for host, entry in seen.items():
        if entry["foreign"]:
            out[host] = {
                "relation": RETAINED,
                "carried": True,
                "why": ("a canary planted in an EARLIER run left during a "
                        "later one, so the tool retained input across calls"),
            }
        elif entry["carried"]:
            runs_hit = len(set(entry["carried"]))
            out[host] = {
                "relation": INPUT_DEPENDENT,
                "carried": True,
                "why": ("the canary planted in each run left in that same run "
                        "({} of {} runs), so this egress carries whatever the "
                        "tool is given".format(runs_hit, len(runs))),
            }
        elif entry["opaque"]:
            out[host] = {
                "relation": UNEXAMINED,
                "carried": None,
                "why": ("{} payload(s) to this host could not be decoded, so "
                        "whether they carried the input is unknown"
                        .format(entry["opaque"])),
            }
        elif len(entry["contacted"]) == len(runs):
            out[host] = {
                "relation": INPUT_INDEPENDENT,
                "carried": False,
                "why": ("contacted in every run with fully examined payloads "
                        "and no canary in any of them, so this egress does "
                        "not carry the input"),
            }
        else:
            out[host] = {
                "relation": INPUT_INDEPENDENT,
                "carried": False,
                "why": ("contacted in {} of {} runs, payloads examined, no "
                        "canary present".format(len(entry["contacted"]),
                                                len(runs))),
            }
    return out


def summarise(table):
    """One line per destination, ordered worst first."""
    order = {RETAINED: 0, INPUT_DEPENDENT: 1, UNEXAMINED: 2,
             INPUT_INDEPENDENT: 3}
    rows = sorted(table.items(), key=lambda kv: order.get(kv[1]["relation"], 9))
    return ["{} -> {}: {}".format(h, v["relation"], v["why"])
            for h, v in rows]
