# Filter rules

For noise-agent.py's proposer, and for anyone writing filters by hand. A filter hides events from every detection rule, so always ask: "would this hide an attacker doing the same?" If yes, narrow it or don't filter.

## Never filter

Logins, remote access, privilege or user changes, credential access, persistence, firewall or audit changes, security tools, or anything from a user-writable path. Allow `ptrace`, `memfd_create` and similar (`pinned_actions`) only when the program and its parent are both fixed, like a browser's crash handler watching its own browser (the code checks enforce this).

## Internet-facing programs

Browsers, mail, chat and office apps (`internet_facing` in `safety.json`) are where exploits land, so their `pinned_actions` need more:

- `memfd_create`: only in helpers the app starts itself (parent executable is the same as the program, never the top-level process). Also pin `process.Ext.memfd.name` to the app's own exact name and `process.Ext.memfd.flag_noexec_seal=true`, so a memfd that could be executed stays visible.
- `ptrace` and other pinned actions: only the app's own helper in the app's folder (like its crash handler), never the app itself.
- One long-running process making a steady stream all day is usually a page or extension left open: put that in fix_at_source too.

## Every filter

- Pin what an attacker can't fake: a full path under a root-owned folder, an exact command line, a specific parent. Never `process.name` or a bare name.
- LOL binaries (`lolbins` in `safety.json`) only by exact command line.
- Add `event.category` (unless descendants), plus `event.action`, parent or port to narrow it.
- No home, temp or relative paths, and no values that change on restart.
- Pin the process itself, not just its parent. No URL, IP or host in a command line: those are beacons or healthchecks.
- Needs `--allow`? Then it's a suggestion, not a filter.

## How to work

1. Check every row, including "Not proposed": a "too broad" row often hides a narrow filter.
2. Filter the exact command an app repeats, not everything it starts.
3. Wildcard random IDs (container IDs, hashes) by whole folder, or skip the row.
4. A one-hour burst isn't steady noise: check with `explain`. The agent's code checks refuse bursts.
5. Faults, frequent healthchecks, scanning or beaconing go in fix_at_source, never in a filter.

When unsure, don't filter: suggest it.
