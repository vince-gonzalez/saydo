# What MCP tools actually do with your data

DRAFT. Wording is a placeholder pending the author's pass.

A behavioural sweep of 36 MCP servers discovered from public package registries, executed inside a sandbox with no route out except a recording proxy. Every finding is something the harness OBSERVED.

## What was actually measured

| outcome | servers |
|---|---|
| exercised successfully | 19 |
| would not start | 17 |
| could not be installed | 0 |
| harness refused | 0 |
| errored | 0 |

Only the first row supports any claim about behaviour. Most MCP servers require a credential, and one that declined to run without a credential has not been shown to be safe -- it has not been shown anything. Every rate below is over the 19 exercised servers, not the 36 discovered ones.

Of the 19 that started, **19 did nothing observable**: they listed their tools and then made no network call the harness could see, because a tool invoked with placeholder arguments and no credential usually rejects the call before it does any work. Those servers have NOT been shown to be well behaved. Nothing was established about them in either direction, and they are excluded from every rate below rather than counted as clean.

## The finding is about auditability, not about safety

Not one server that started could be made to act. This run therefore says nothing about whether any of them exfiltrate data, and it would be dishonest to present it as though it did.

It does say something worth saying: **an MCP server is very hard to audit from the outside.** Behaviour appears only when a tool is given credentials and inputs it accepts, which an auditor examining someone else's server does not have. That is precisely the argument for the author DECLARING what a tool does, and for conformance being checked where the credentials already are - in the publisher's own CI - rather than guessed at from outside.

## How to argue with this

- Servers were run without credentials, so a credentialed server may do more than is recorded here. Every figure is a lower bound.
- Each server was exercised with benign placeholder arguments, not a real workload.
- TLS inspection is cooperative: a tool that pins its certificates refuses examination, and is reported as unexamined rather than clean.
- The corpus is what public registries advertise, which is not the same as what people actually install.
- Every measurement is reproducible: the harness, the declarations and the receipts are in this repository.

Merged from 3 batch file(s).

