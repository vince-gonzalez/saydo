# What MCP tools actually do — a first SayDo sweep

DRAFT. A conservative behavioral sweep of 4 third-party MCP servers, run with SayDo on 2026-08-29. Every finding is something the harness OBSERVED, not inferred from the description. It is a lower bound: servers were driven with benign placeholder arguments, so tools needing specific valid input may do less here than in real use.

Headline: 2 of 4 servers touched the network, the filesystem, or another process in a way their terse tool descriptions do not state; 4 such observations in total.

How to read this. A finding is not an accusation. Some are surprising (a URL fetcher that also spawns a subprocess); others are expected of the tool but unstated where an agent reads it (a git tool that writes inside .git and shells out to git). The point is the same: the actual footprint is made visible and verifiable, instead of left to a one-line description. Servers that show no finding were either clean or not fully exercised by benign input; both are marked, and neither is a clean bill.

This write-up is a DRAFT and its wording is a placeholder. Any public version ships in the owner's words.

## mcp-server-time
- expected: timezone math; should touch nothing
- tools: get_current_time, convert_time
- verdict: **draft**  (checks: {'pass': 3, 'not-covered': 1})
- no behavior beyond the conservative envelope was observed under benign input.
- receipt head: `f8b83b9b3a041f80d2f513515a67df62456f2f11ffa1e536ca647aa39c899908`

## mcp-server-fetch
- expected: fetches URLs; network by design
- tools: fetch
- verdict: **failing**  (checks: {'fail': 2, 'pass': 1, 'not-covered': 1})
- behavior beyond a conservative envelope:
  - `network.none` (no-network): egress: fetch->example.com
  - `subprocess.none` (no-subprocess): subprocess: fetch:subprocess.Popen; fetch:subprocess.Popen
- receipt head: `729fcb24fc3f148713cb8038c6f3b0afbd019fe3d1112443a6436b112fb358d1`

## mcp-server-git
- expected: git operations; subprocess + filesystem likely
- tools: git_status, git_diff_unstaged, git_diff_staged, git_diff, git_commit, git_add, git_reset, git_log, git_create_branch, git_checkout, git_show, git_branch
- verdict: **failing**  (checks: {'pass': 1, 'fail': 2, 'not-covered': 1})
- behavior beyond a conservative envelope:
  - `writes.none` (no-write): write: git_commit:C:\Users\Admin\OneDrive\Desktop\saydo\fixtures\gitrepo\.git\COMMIT_EDITMSG; git_commit:C:\Users\Admin\OneDrive\Desktop\saydo\fixtures\gitrepo\.git\COMMIT_EDITMSG; git_commit:C:\Users\Admin\OneDrive\Desktop\saydo\fixtures\gitrepo\.git\refs\heads\master.lock; git_commit:C:\Users\Admin\OneDrive\Desktop\saydo\fixtures\gitrepo\.git\refs\heads\master; git_commit:C:\Users\Admin\OneDrive\Desktop\saydo\fixtures\gitrepo\.git\refs\heads\master.lock; git_commit:C:\Users\Admin\OneDrive\Desktop\saydo\fixtures\gitrepo\.git\logs\refs\heads\master.lock
  - `subprocess.none` (no-subprocess): subprocess: git_add:subprocess.Popen; git_checkout:subprocess.Popen; git_checkout:subprocess.Popen; git_commit:subprocess.Popen; git_commit:subprocess.Popen; git_commit:subprocess.Popen
- receipt head: `07bfa97f5d3121dc000ac4c81d3dbcf22a61afed9931abd9c3266d6910f99753`

## mcp-server-sqlite
- expected: sqlite; filesystem writes likely
- tools: read_query, write_query, create_table, list_tables, describe_table, append_insight
- verdict: **draft**  (checks: {'pass': 3, 'not-covered': 1})
- no behavior beyond the conservative envelope was observed under benign input.
- receipt head: `fb4837c3ab99e703389fa898688847c82bc7053348c6b0cde33efa8f5b0723e0`

