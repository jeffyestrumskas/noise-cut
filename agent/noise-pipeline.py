#!/usr/bin/env python3
r"""The steps of Agent mode that use no model. deploy/run.sh runs them around noise-agent.py.

  noise-pipeline.py rows              noisiest rows             -> OUT/rows.json     (read-only key)
  noise-pipeline.py apply --dry-run   check, create nothing     -> OUT/summary.txt   (read-only key)
  noise-pipeline.py apply             create what passed        -> OUT/summary.txt   (event filter key)
  noise-pipeline.py revert --since 7d delete filters the pipeline created

apply creates a filter only if the validator approved exactly it and it passes noise_gate.py again with
fresh counts. Of overlapping filters only the narrowest is created, at most --max-filters per run.
Created filters are marked "noise-agent:"; --dry-run never loads noise-cut.py.

Settings: --env-file (default config/agent.env). Key: --key-file; rows and --dry-run use
config/read.env, apply and revert config/write.env. A DISABLED file in --out stops every command.
"""
import argparse
import contextlib
import datetime
import importlib.util
import io
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)  # the shared code: noise_rules, es_read, explain, noise-cut
sys.path[:0] = [HERE, ROOT]
import noise_gate as ng  # noqa: E402
import noise_rules as nr  # noqa: E402
from es_read import Search  # noqa: E402

AGENT_ENV = os.path.join(HERE, "config", "agent.env")
READ_KEY = os.path.join(HERE, "config", "read.env")
WRITE_KEY = os.path.join(HERE, "config", "write.env")
MARKER = "noise-agent:"


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


def safe_text(s, n=200):
    return re.sub(r"\s+", " ", re.sub(r"[^\x20-\x7e]", " ", str(s or ""))).strip()[:n]


def writer():
    """noise-cut.py, the only code that creates or deletes filters. Loaded by apply and revert only."""
    spec = importlib.util.spec_from_file_location("noise_cut", os.path.join(ROOT, "noise-cut.py"))
    en = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(en)
    return en


def write_api(a):
    """noise-cut.py's Api for the apply key, after checking the key can't do more than it needs."""
    Search(a.env_file, a.key_file).require_key("apply")
    en = writer()
    os.environ["ELASTIC_ENV_FILE"] = a.env_file
    en.init_state()
    return en, en.Api(a.key_file)


# ---------------------------------------------------------------- rows

def cmd_rows(a):
    """The noisiest rows, proposed and 'Not proposed', from noise-cut.py's listing code."""
    Search(a.env_file, a.key_file).require_read_only()
    en = writer()  # for its listing code only; the key is read-only, checked above
    os.environ["ELASTIC_ENV_FILE"] = a.env_file
    en.init_state()
    args = argparse.Namespace(top=a.rows, since=a.since, host=None, term=[], index="logs-*")
    with contextlib.redirect_stdout(io.StringIO()):
        total, proposals, skipped = en.find_candidates(en.Api(a.key_file), args)
    path = os.path.join(a.out, "rows.json")
    with open(path, "w") as fh:
        json.dump({"created": now_iso(), "since": a.since, "total": total,
                   "proposals": proposals, "skipped": skipped}, fh, indent=1)
    print(f"rows: {total:,} events over {a.since}; {len(proposals)} proposed and {len(skipped)} "
          f"not-proposed rows in {path}")


# ---------------------------------------------------------------- apply

def cmd_apply(a):
    search = Search(a.env_file, a.key_file)
    if a.dry_run:
        search.require_read_only()
    else:
        en, api = write_api(a)
    out = lambda name: os.path.join(a.out, name)  # noqa: E731
    with open(out("proposals.json")) as fh:
        props = json.load(fh)
    if not os.path.exists(out("verdicts.json")):
        msg = "noise-agent: no verdicts (validation did not finish); nothing applied."
        with open(out("summary.txt"), "w") as fh:
            fh.write(msg + "\n")
        sys.exit(msg)
    with open(out("verdicts.json")) as fh:
        verdicts = json.load(fh).get("verdicts", {})
    total = ng.total_events(search, a.since)
    ready, rejected = [], []
    for f in props.get("filters", []):
        v = verdicts.get(str(f.get("id")), {"approve": False, "reason": "not reviewed"})
        why, n, hosts = ng.gate(search, f, total, a.since, a.max_share)  # again, with fresh counts
        if why:
            rejected.append((f, "code: " + "; ".join(why)))
        elif v.get("approve") is not True:
            rejected.append((f, "validator: " + safe_text(v.get("reason"), 300)))
        elif v.get("fingerprint") != ng.fingerprint(f):
            rejected.append((f, "code: the approved filter differs from this one"))
        else:
            ready.append((n, f, hosts))
    # Overlaps (several rows often land on one stream): keep only the narrowest. A filter whose
    # conditions another approved filter has too, plus more, is dropped; of identical ones, the first.
    overlap = []
    for i, (n, f, hosts) in enumerate(ready):
        by = next((g for j, (_, g, _) in enumerate(ready) if j != i and ng.contains(f, g)
                   and (not ng.contains(g, f) or j < i)), None)
        if by:
            overlap.append((f, by))
    dropped = {id(f) for f, _ in overlap}
    ready = [r for r in ready if id(r[1]) not in dropped]
    ready.sort(key=lambda x: x[0])  # narrowest first: the cap never favours the broadest filters
    held = ready[a.max_filters:]
    created = []
    for n, f, hosts in ready[:a.max_filters]:
        if os.path.exists(out("DISABLED")):
            held.append((n, f, hosts))
            continue
        note = f"{MARKER} {safe_text(f.get('note'), 150)}"
        c = ng.canonical(f)
        entries = ng.to_entries(f)
        shown = safe_text(f"{c['os']}{' descendants of' if c['descendants'] else ''}: " + " ".join(
            f"{e['field']}{'~' if e['type'] == 'wildcard' else ''}={e['value']}" for e in entries), 600)
        hosts = [safe_text(h, 80) for h in hosts]
        if a.dry_run:
            ok, result = True, "dry run: not created"
        else:
            tags = [en.DESCENDANTS_TAG] if c["descendants"] else []
            item = en.make_item(argparse.Namespace(policy=None), c["os"], entries, tags, note)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                en.create_items(api, argparse.Namespace(dry_run=False, yes=True), [item])
            result = next((ln for ln in buf.getvalue().splitlines() if ln.startswith(("created:", "exists already:"))),
                          buf.getvalue().strip()[-300:])
            ok = result.startswith(("created:", "exists already:"))
        created.append({"id": f["id"], "ok": ok, "events": n, "hosts": hosts, "note": note,
                        "filter": shown, "fingerprint": ng.fingerprint(f), "output": result})

    lines = [f"noise-agent {'DRY RUN ' if a.dry_run else ''}{now_iso()[:16]}: "
             f"{sum(c['ok'] for c in created)} filters {'would be ' if a.dry_run else ''}created, "
             f"{len(rejected)} rejected, {len(overlap)} overlapping, {len(held)} held (limit {a.max_filters}/run). "
             f"Events over {a.since}: {total:,}."]
    for c in created:
        lines.append(f"  {'+' if c['ok'] else 'FAILED'} {c['events']:,} [{', '.join(c['hosts'])}] {c['note']}")
        lines.append(f"      {c['filter'][:300]}")
    for f, why in rejected:
        lines.append(f"  - {safe_text(f.get('note'), 80)}: {why}")
    for f, by in overlap:
        lines.append(f"  ~ {safe_text(f.get('note'), 80)}: overlaps {safe_text(by.get('note'), 80)} (kept, narrower)")
    for n, f, hosts in held:
        lines.append(f"  = held for next run: {safe_text(f.get('note'), 80)} ({n:,})")
    # Model-written text: shown for a human to judge, never acted on.
    for s in props.get("suggestions", []):
        lines.append(f"  ? (model text, unverified) needs you: {safe_text(s, 300)}")
    for s in props.get("fix_at_source", []):
        lines.append(f"  ! (model text, unverified) look at: {safe_text(s, 300)}")
    summary = "\n".join(lines)
    with open(out("summary.txt"), "w") as fh:
        fh.write(summary + "\n")
    with open(out("applied.json"), "w") as fh:
        json.dump({"created": now_iso(), "dry_run": a.dry_run, "filters": created,
                   "rejected": [{"id": f.get("id"), "why": w} for f, w in rejected],
                   "overlapping": [{"id": f.get("id"), "kept": by.get("id")} for f, by in overlap]}, fh, indent=1)
    print(summary)
    sys.exit(0 if all(c["ok"] for c in created) else 1)


# ---------------------------------------------------------------- revert

def cmd_revert(a):
    en, api = write_api(a)
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=nr.window_seconds(a.since))
    mine = [i for i in en.all_filters(api) if MARKER in (i.get("description") or "")
            and datetime.datetime.fromisoformat(i["created_at"].replace("Z", "+00:00")) >= cutoff]
    if not mine:
        print(f"No filters created by noise-agent in the last {a.since}.")
        return
    for i in mine:
        print(f"{i['created_at'][:16]}  {i['item_id']}  {i['name']}")
    if not a.yes:
        if not sys.stdin.isatty() or input(f"Delete these {len(mine)}? [y/N] ").strip().lower() not in ("y", "yes"):
            sys.exit("Nothing deleted.")
    for i in mine:
        en.delete_rule(api, argparse.Namespace(delete_rule=i["item_id"], yes=True))


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
                                allow_abbrev=False)
    sub = p.add_subparsers(dest="cmd", required=True)
    common = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    common.add_argument("--out", default=os.path.join(HERE, "runs"),
                        help="run folder (default runs/ here)")
    common.add_argument("--since", help="window (default 24h; for revert 7d)")
    common.add_argument("--env-file", default=AGENT_ENV,
                        help="settings file: ELASTIC_URL, limits (default config/agent.env)")
    common.add_argument("--key-file", help="file with ELASTIC_API_KEY=<key> (default config/read.env for rows "
                                           "and --dry-run, write.env for apply and revert)")
    rp = sub.add_parser("rows", parents=[common], help="noisiest rows -> OUT/rows.json", allow_abbrev=False)
    rp.add_argument("--rows", type=int, default=20)
    ap = sub.add_parser("apply", parents=[common], help="create what passed both", allow_abbrev=False)
    ap.add_argument("--dry-run", action="store_true", help="check everything, create nothing (read-only key)")
    ap.add_argument("--max-filters", type=int, help="most filters created per run ($NOISE_MAX_FILTERS, default 5)")
    ap.add_argument("--max-share", type=float, help="largest share of all events one filter may hide "
                                                    "($NOISE_MAX_SHARE, default 1 = no limit)")
    rv = sub.add_parser("revert", parents=[common], help="delete filters noise-agent created", allow_abbrev=False)
    rv.add_argument("--yes", "-y", action="store_true")
    a = p.parse_args()
    read_only = a.cmd == "rows" or (a.cmd == "apply" and a.dry_run)
    a.env_file = os.path.expanduser(a.env_file)
    if not os.path.exists(a.env_file):
        sys.exit(f"No {a.env_file}.")
    conf = nr.read_env_file(a.env_file)
    # The key: --key-file, else read.env / write.env, unless the settings file carries it (as the
    # per-step settings files that deploy/run.sh writes do).
    a.key_file = a.key_file or (None if conf.get("ELASTIC_API_KEY") else (READ_KEY if read_only else WRITE_KEY))
    a.since = a.since or ("7d" if a.cmd == "revert" else "24h")
    if nr.window_seconds(a.since) is None:
        sys.exit("--since must look like 24h or 7d")
    if a.cmd == "apply":
        a.max_filters = max(0, a.max_filters if a.max_filters is not None else int(conf.get("NOISE_MAX_FILTERS", "5")))
        a.max_share = min(1.0, max(0.0, a.max_share if a.max_share is not None else float(conf.get("NOISE_MAX_SHARE", "1"))))
    os.makedirs(a.out, exist_ok=True)
    if os.path.exists(os.path.join(a.out, "DISABLED")):
        sys.exit(f"{os.path.join(a.out, 'DISABLED')} exists: doing nothing.")
    nr.load_safety()  # safety.json (+ local overrides); no --allow here, ever
    {"rows": cmd_rows, "apply": cmd_apply, "revert": cmd_revert}[a.cmd](a)


if __name__ == "__main__":
    main()
