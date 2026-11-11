#!/usr/bin/env python3
r"""Find the noisiest Elastic Defend events and turn them into event filters.

  noise-cut.py                         the 10 best filters to add, numbered (last 24h)
  noise-cut.py --since 6h --top 30     different window / more rows
  noise-cut.py --host web01.example   only count events from one host
  noise-cut.py --ignore-rule 3         show candidate 3 as an event filter, ask, create it
  noise-cut.py --ignore-rule 3,5,8-10 --yes
  noise-cut.py --list-filters          list the event filters that exist now (or --rules)
  noise-cut.py --delete-rule ITEM_ID   delete one (ITEM_ID from --list-filters)
  noise-cut.py --breakdown             plain counts per field (dataset, host, process...)
  noise-cut.py --json                  the same list as JSON

Build a filter by hand (e.g. with a wildcard so it survives app updates):
  noise-cut.py --count --os macos --match event.category=file \
      --wildcard 'process.executable=/Applications/Brave Browser.app/*/Brave Browser Helper'
  noise-cut.py --add-filter --os macos --match event.category=file \
      --wildcard 'process.executable=/Applications/Brave Browser.app/*/Brave Browser Helper' \
      --note "Brave helper cache churn"
  noise-cut.py --add-filter --os linux --descendants \
      --match 'process.command_line=/bin/bash /opt/monitoring/poll.sh'
--count shows how many events those conditions matched over --since (use it before
creating, and again with --since 15m afterwards to confirm the filter works).

Candidates come in three kinds:
  exe       process.executable + event.category
  cmd       process.command_line + event.category
  children  process.command_line, as a Defend "Process Descendants" filter
Filters are global unless you pass --policy ID (see --policies). Version folders are already
wildcarded. Risky rows (shells, cron, LOL binaries, user-writable paths) are listed as "Not proposed";
the lists are in safety.json, override them in safety.local.json or with --allow NAME.

Settings: --env-file FILE (default config/user.env): ELASTIC_URL, ELASTIC_API_KEY, optional KIBANA_URL.
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import shlex
import shutil
import sys
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from noise_rules import (load_safety, read_env_file, read_key_file, basename, program, risk, skip_reason,  # noqa: E402
                         make_entries, window_seconds, conditions_risk, term_or_wildcard, es_condition)
USER_ENV = os.path.join(HERE, "config", "user.env")
ENV_FILE = None  # the file ELASTIC_API_KEY came from, for messages
# --ignore-rule N refers to the numbers printed by the last listing, saved here.
# Older lists are refused: the numbers shift as the noise changes.
CACHE_MAX_AGE = datetime.timedelta(minutes=15)
# Copy of the existing event filters, refreshed whenever a key that can read them is used, so a
# read-only key can still hide rows that are already filtered.
# Both live in one state dir shared by every run (by hand or noise-agent): $NOISE_CUT_STATE,
# default ~/.local/share/noise-cut. Files from older versions (beside this script) are copied there.
STATE_DIR = (os.environ.get("NOISE_CUT_STATE") or os.environ.get("ELASTIC_NOISE_STATE")  # the old name still works
             or next((d for d in map(os.path.expanduser, ("~/.local/share/noise-cut", "~/.local/share/elastic-noise"))
                      if os.path.isdir(d)), os.path.expanduser("~/.local/share/noise-cut")))
FILTERS_RECORD = os.path.join(STATE_DIR, ".existing-filters.json")
CACHE_FILE = os.path.join(STATE_DIR, ".last-candidates.json")


def init_state():
    os.makedirs(STATE_DIR, exist_ok=True)
    for path in (FILTERS_RECORD, CACHE_FILE):
        old = os.path.join(HERE, os.path.basename(path))
        if not os.path.exists(path) and os.path.exists(old):
            shutil.copy2(old, path)

EVENT_FILTERS_LIST = "endpoint_event_filters"
DESCENDANTS_TAG = "filter_process_descendants"
ITEM_PREFIX = "noise-cut-"
OWN_PREFIXES = (ITEM_PREFIX, "elastic-noise-")  # filters made before the rename keep their old item_id

# Fields that usually identify where a log line came from. Missing ones are skipped.
DEFAULT_FIELDS = [
    "data_stream.dataset",
    "host.name",
    "container.name",
    "container.image.name",
    "log.file.path",
    "systemd.unit",
    "process.name",
]

def load_env(key_file=None):
    """(ELASTIC_URL, KIBANA_URL, key) from one file, never from the environment. With key_file (as
    noise-pipeline.py passes read.env or write.env), the key comes from that file instead."""
    global ENV_FILE
    ENV_FILE = os.path.expanduser(os.environ.get("ELASTIC_ENV_FILE") or USER_ENV)
    if not os.path.exists(ENV_FILE):
        sys.exit(f"{ENV_FILE} not found (copy config/user.env.example there, or pass --env-file).")
    conf = read_env_file(ENV_FILE)
    url, key = conf.get("ELASTIC_URL"), conf.get("ELASTIC_API_KEY")
    if key_file:
        key, ENV_FILE = read_key_file(key_file), key_file
    if not url or not key:
        sys.exit(f"Set ELASTIC_URL and ELASTIC_API_KEY in {ENV_FILE}.")
    url = url.rstrip("/")
    kibana = conf.get("KIBANA_URL", url.replace(".es.", ".kb.", 1)).rstrip("/")
    return url, kibana, key


class Api:
    def __init__(self, key_file=None):
        self.es_url, self.kb_url, self.key = load_env(key_file)
        print(f"(using the API key from {ENV_FILE})", file=sys.stderr)

    def _call(self, method, url, body=None, kibana=False, ok404=False, soft=False):
        headers = {"Authorization": f"ApiKey {self.key}", "Content-Type": "application/json"}
        if kibana:
            headers.update({"kbn-xsrf": "true", "elastic-api-version": "2023-10-31"})
        req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None,
                                     headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if (ok404 and e.code == 404) or (soft and e.code in (401, 403, 404)):
                return None
            msg = e.read().decode()[:1500]
            hint = f"\n(API key from {ENV_FILE})"
            if e.code == 403 and kibana:
                hint += ("\nThe API key lacks Kibana privileges. Event filters need Security > "
                        "'Event Filters: All' and 'Global artifact management: All'.")
            sys.exit(f"HTTP {e.code} on {method} {url}\n{msg}{hint}")

    def es(self, path, body=None):
        return self._call("POST" if body is not None else "GET", self.es_url + path, body)

    def kb(self, method, path, body=None, ok404=False, soft=False):
        return self._call(method, self.kb_url + path, body, kibana=True, ok404=ok404, soft=soft)


def base_query(a):
    query = {"bool": {"filter": [{"range": {"@timestamp": {"gte": f"now-{a.since}"}}}]}}
    if a.host:
        query["bool"]["filter"].append({"term": {"host.name": a.host}})
    for t in a.term:
        f, v = t.split("=", 1)
        query["bool"]["filter"].append(term_or_wildcard(f, v))
    return query


def scope_text(a):
    return (f"over the last {a.since}" + (f" on host {a.host}" if a.host else "")
            + "".join(f", {t}" for t in a.term))


# ---------------------------------------------------------------- candidates

def multi_terms(fields, size):
    return {"multi_terms": {"terms": [{"field": f} for f in fields], "size": size},
            "aggs": {"hosts": {"terms": {"field": "host.name", "size": 3}},
                     "actions": {"terms": {"field": "event.action", "size": 2}}}}


# When one event.action is at least this share of a row, the filter is pinned to that action,
# so the program's other activity (e.g. the processes it starts) stays visible.
ACTION_SHARE = 0.95


def every(runs, seconds):
    if not seconds or runs < 2:
        return ""
    gap = seconds / runs
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if gap >= size:
            return f"every {gap / size:.0f}{unit}"
    return f"every {gap:.0f}s"


def save_record(items):
    keep = [{k: it[k] for k in ("item_id", "name", "os_types", "tags", "entries")} for it in items]
    with open(FILTERS_RECORD, "w") as f:
        json.dump({"updated": now_iso(), "filters": keep}, f, indent=1)


def existing_filters(api):
    """(filters, where they came from). Refreshes the local record when Kibana is readable."""
    items = all_filters(api, soft=True)
    if items is not None:
        save_record(items)
        return items, "Kibana"
    if os.path.exists(FILTERS_RECORD):
        with open(FILTERS_RECORD) as f:
            rec = json.load(f)
        return rec["filters"], f"the local record from {rec['updated']} (this key can't read filters)"
    return [], "nowhere (this key can't read filters and there's no local record yet)"


def entry_key(e):
    return (e["field"], e["type"], e["operator"], json.dumps(e.get("value")))


def covered_by(row, filters):
    """The existing filter that already drops everything this row would, or None.
    A filter covers a row when it's for the same OS and type and all its conditions are in the row."""
    row_keys = {entry_key(e) for e in row["entries"]}
    for f in filters:
        if row["os"] not in f["os_types"] or (DESCENDANTS_TAG in f["tags"]) != (DESCENDANTS_TAG in row["tags"]):
            continue
        if not any(t in ("policy:all",) for t in f["tags"]):
            continue  # policy-scoped filters only cover some hosts
        if f["entries"] and all(entry_key(e) in row_keys for e in f["entries"]):
            return f
    return None


def find_candidates(api, a):
    """Rank filter proposals. Returns (total, proposals, skipped)."""
    size = max(a.top * 3, 60)
    body = {"size": 0, "track_total_hits": True, "query": base_query(a), "aggs": {
        "exe": multi_terms(["host.os.type", "event.category", "process.executable"], size),
        "cmd": multi_terms(["host.os.type", "event.category", "process.executable", "process.command_line"], size),
        "children": multi_terms(["host.os.type", "process.parent.executable", "process.parent.command_line"], size),
        # How often each command line starts, to show how often a polled command runs.
        "runs": {"filter": {"terms": {"event.action": ["exec", "start"]}},
                 "aggs": {"cmd": {"terms": {"field": "process.command_line", "size": 2000}}}},
    }}
    res = api.es(f"/{a.index}/_search?ignore_unavailable=true", body)
    total = res["hits"]["total"]["value"]
    aggs = res["aggregations"]
    runs = {b["key"]: b["doc_count"] for b in aggs["runs"]["cmd"]["buckets"]}
    seconds = window_seconds(a.since)

    rows = {}
    for kind in ("exe", "cmd", "children"):
        for b in aggs[kind]["buckets"]:
            keys = b["key"]
            os_type, value = keys[0], keys[-1]
            if os_type not in ("linux", "macos", "windows") or not str(value).strip():
                continue
            category = "process" if kind == "children" else keys[1]
            executable = keys[-2] if kind != "exe" else value
            acts = b["actions"]["buckets"]
            action = (acts[0]["key"] if kind != "children" and acts
                      and acts[0]["doc_count"] >= ACTION_SHARE * b["doc_count"] else None)
            entries = make_entries(kind, category, value, action)
            tags = [DESCENDANTS_TAG] if kind == "children" else []
            key = json.dumps([os_type, entries, tags])
            hosts = [h["key"] for h in b["hosts"]["buckets"]]
            if key in rows:  # e.g. two app versions that now share one wildcard
                r = rows[key]
                r["count"] += b["doc_count"]
                r["hosts"] = list(dict.fromkeys(r["hosts"] + hosts))[:3]
                continue
            rows[key] = {
                "kind": kind, "os": os_type, "category": category, "executable": executable,
                "count": b["doc_count"], "hosts": hosts, "entries": entries, "tags": tags, "action": action,
                "title": conditions_text(entries), "risk": "",
                "every": "" if kind == "exe" else every(runs.get(value, 0), seconds),
                "skip": skip_reason(kind, value, executable),
            }

    filters, a.filters_source = existing_filters(api)
    proposals, skipped, exe_keys, a.n_covered = [], [], set(), 0
    # Commands whose children are filtered (or proposed): a cmd row for the same command is mostly
    # its subshells, which that filter already drops; the rest is the command's own run, worth keeping.
    children_cmds = {r["entries"][0]["value"] for r in rows.values()
                     if r["kind"] == "children" and covered_by(r, filters)}
    for r in sorted(rows.values(), key=lambda r: -r["count"]):
        exe_key = (r["os"], r["category"], r["executable"], r["action"])
        if r["kind"] == "cmd" and r["entries"][0]["value"] in children_cmds:
            continue
        if r["kind"] == "cmd" and exe_key in exe_keys:
            continue  # same events as an executable filter that exists or is proposed above
        if covered_by(r, filters):
            a.n_covered += 1
            if r["kind"] == "exe":
                exe_keys.add(exe_key)
            continue
        if r["skip"]:
            skipped.append(r)
            continue
        if r["kind"] == "exe":
            exe_keys.add(exe_key)
        if r["kind"] == "children":
            children_cmds.add(r["entries"][0]["value"])
        proposals.append(r)
    return total, proposals[: a.top], skipped[: a.top]


def show_candidates(api, a):
    total, cands, skipped = find_candidates(api, a)
    with open(CACHE_FILE, "w") as f:
        json.dump({"created": now_iso(), "scope": scope_text(a), "total": total, "candidates": cands}, f, indent=1)
    if a.json:
        print(json.dumps({"total": total, "scope": scope_text(a), "skipped": skipped,
                          "proposals": [dict(c, row=i) for i, c in enumerate(cands, 1)]}, indent=1))
        return
    print(f"{total:,} events in {a.index} {scope_text(a)}")
    print(f"{a.n_covered} rows hidden because a filter already covers them (filters from {a.filters_source}).\n")
    if not total:
        return
    print(f"{'#':>3}  {'events':>11}  {'share':>6}  {'os':<6} {'kind':<8} {'runs':<10} filter  [hosts]")
    for i, c in enumerate(cands, 1):
        print(f"{i:>3}  {c['count']:>11,}  {c['count'] / total:6.1%}  {c['os']:<6} {c['kind']:<8} "
              f"{c['every']:<10} {c['title']}  [{', '.join(c['hosts'])}]")
    if skipped:
        print("\nNot proposed:")
        for c in skipped:
            print(f"     {c['count']:>11,}  {c['count'] / total:6.1%}  {c['os']:<6} {c['kind']:<8} "
                  f"{c['every']:<10} {c['title']}\n{'':>40}-> {c['skip']}")
    print("\nexe      = that program's events of that category"
          "\ncmd      = that exact command line's events of that category"
          "\nchildren = everything started under that command line (the command itself stays visible)"
          "\nruns     = how often the command starts; a very short gap may be a fault worth fixing at the source"
          f"\nevent.action is added when one action is {ACTION_SHARE:.0%}+ of a row, to keep the rest visible"
          "\n~=       = wildcard: version/ID folders replaced by * so the filter survives updates"
          "\n\nNext: noise-cut.py --ignore-rule N   (shows the exact filter and asks first)")


def shorten(s, n):
    return s if len(s) <= n else s[: n - 3] + "..."


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


# ---------------------------------------------------------------- event filters

def conditions_text(entries):
    return " ".join(f"{e['field']}{'~=' if e['type'] == 'wildcard' else '='}{e['value']}" for e in entries)


def make_item(a, os_type, entries, extra_tags, description):
    tags = list(extra_tags) + ([f"policy:{p}" for p in a.policy] if a.policy else ["policy:all"])
    digest = hashlib.sha256(json.dumps([os_type, entries, sorted(tags)]).encode()).hexdigest()[:16]
    return {
        "list_id": EVENT_FILTERS_LIST,
        "item_id": ITEM_PREFIX + digest,
        "namespace_type": "agnostic",
        "type": "simple",
        "name": shorten(f"{os_type}: {'descendants of ' if DESCENDANTS_TAG in extra_tags else ''}"
                        f"{conditions_text(entries)}", 256),
        "description": shorten(f"Added by noise-cut.py {now_iso()[:10]}. {description}", 256),
        "os_types": [os_type],
        "tags": tags,
        "entries": entries,
    }


def filter_item(c, a, cache):
    return make_item(a, c["os"], c["entries"], c["tags"],
                     f"{c['count']:,} events {cache['scope']} from {', '.join(c['hosts'])}.")


def ensure_list(api):
    q = urllib.parse.urlencode({"list_id": EVENT_FILTERS_LIST, "namespace_type": "agnostic"})
    if api.kb("GET", f"/api/exception_lists?{q}", ok404=True) is None:
        print("Creating the Event Filters list (first filter in this project).")
        api.kb("POST", "/api/exception_lists", {
            "list_id": EVENT_FILTERS_LIST, "namespace_type": "agnostic", "type": "endpoint_events",
            "name": "Endpoint Security Event Filters List",
            "description": "Endpoint Security Event Filters List", "tags": [], "os_types": []})


def describe_item(item):
    lines = [f"  name:    {item['name']}", f"  os:      {item['os_types'][0]}",
             f"  scope:   {', '.join(t for t in item['tags'] if t.startswith('policy:'))}"]
    if DESCENDANTS_TAG in item["tags"]:
        lines.append("  type:    Process Descendants (the process itself is kept, everything it starts is dropped;"
                     " Kibana adds 'event.category is process')")
    for e in item["entries"]:
        val = e.get("value")
        verb = {"wildcard": "matches", "match_any": "is one of"}.get(e["type"], "is")
        if e["operator"] != "included":
            verb = {"matches": "does not match", "is one of": "is not one of"}.get(verb, "is not")
        lines.append(f"  match:   {e['field']} {verb} "
                     f"{json.dumps(val) if isinstance(val, str) else val}")
    return "\n".join(lines)


def rule_numbers(specs):
    """'3,5,8-10' (repeatable) -> [3, 5, 8, 9, 10], in order, without duplicates."""
    nums = []
    for spec in specs:
        for part in spec.replace(" ", "").split(","):
            if not part:
                continue
            lo, _, hi = part.partition("-")
            if not lo.isdigit() or (hi and not hi.isdigit()):
                sys.exit(f"--ignore-rule: '{part}' isn't a number or range like 8-10")
            nums += range(int(lo), int(hi or lo) + 1)
    return list(dict.fromkeys(nums))


def ignore_rules(api, a):
    if not os.path.exists(CACHE_FILE):
        sys.exit("Run noise-cut.py first to get a numbered list, then --ignore-rule N.")
    with open(CACHE_FILE) as f:
        cache = json.load(f)
    cands = cache["candidates"]
    age = datetime.datetime.now(datetime.timezone.utc) - datetime.datetime.fromisoformat(cache["created"])
    if age > CACHE_MAX_AGE:
        sys.exit(f"The last list is {int(age.total_seconds() // 60)} minutes old (limit "
                 f"{int(CACHE_MAX_AGE.total_seconds() // 60)}). List again (add --top N to see more rows), "
                 f"check the numbers, then --ignore-rule.")
    print(f"Using the list from {cache['created']} ({cache['scope']}).")
    items = []
    for n in rule_numbers(a.ignore_rule):
        if not 1 <= n <= len(cands):
            sys.exit(f"No row {n}; the last list has rows 1-{len(cands)}.")
        c = cands[n - 1]
        if c["risk"] and not a.force:
            sys.exit(f"Row {n} would drop {c['risk']} on every {c['os']} host. Pick a narrower row, "
                     f"or pass --force if you really mean it.")
        item = filter_item(c, a, cache)
        print(f"\n#{n}: about {c['count']:,} events {cache['scope']} [{', '.join(c['hosts'])}]")
        print(describe_item(item))
        if a.dry_run:
            print(json.dumps(item, indent=2))
        items.append(item)
    create_items(api, a, items)


def create_items(api, a, items):
    if a.dry_run:
        print("\n--dry-run: nothing created.")
        return
    if not a.yes:
        if not sys.stdin.isatty():
            sys.exit("\nNot a terminal; re-run with --yes to create these.")
        if input(f"\nCreate {len(items)} event filter(s)? [y/N] ").strip().lower() not in ("y", "yes"):
            sys.exit("Nothing created.")
    ensure_list(api)
    for item in items:
        q = urllib.parse.urlencode({"item_id": item["item_id"], "namespace_type": "agnostic"})
        if api.kb("GET", f"/api/exception_lists/items?{q}", ok404=True) is not None:
            print(f"exists already: {item['item_id']}  {item['name']}")
            continue
        made = api.kb("POST", "/api/exception_lists/items", item)
        print(f"created: {made['item_id']}  {made['name']}")
    refreshed = all_filters(api, soft=True)
    if refreshed is not None:
        save_record(refreshed)
    print("\nDefend agents pick up new filters within a few minutes. Check with:"
          "\n  noise-cut.py --since 15m")


def parse_conditions(a):
    entries = []
    for kind, items in (("match", a.match or []), ("wildcard", a.wildcard or [])):
        for t in items:
            if "=" not in t:
                sys.exit(f"--{kind} needs FIELD=VALUE, got: {t}")
            f, v = t.split("=", 1)
            if not v:
                sys.exit(f"--{kind} {t}: empty value")
            if kind == "wildcard" and "*" not in v and "?" not in v:
                sys.exit(f"--wildcard {t}: no * or ? in the value; use --match instead")
            entries.append({"field": f, "operator": "included", "type": kind, "value": v})
    if not entries:
        sys.exit("Give at least one --match FIELD=VALUE or --wildcard FIELD=PATTERN.")
    if a.os not in ("linux", "macos", "windows"):
        sys.exit("--os must be linux, macos or windows (one per filter).")
    return entries


def count_conditions(api, a):
    entries = parse_conditions(a)
    query = base_query(a)
    query["bool"]["filter"].append({"term": {"host.os.type": a.os}})
    if a.descendants:
        # Events whose parent matches: the direct children. Deeper descendants aren't counted.
        for e in entries:
            if not e["field"].startswith("process.") or e["field"].startswith("process.parent."):
                sys.exit(f"--count --descendants only understands process.* fields, not {e['field']}")
            query["bool"]["filter"].append(es_condition(dict(e, field="process.parent." + e["field"][8:])))
    else:
        query["bool"]["filter"].extend(es_condition(e) for e in entries)
    body = {"size": 0, "track_total_hits": True, "query": query,
            "aggs": {"hosts": {"terms": {"field": "host.name", "size": 10}},
                     "cat": {"terms": {"field": "event.category", "size": 10}}}}
    res = api.es(f"/{a.index}/_search?ignore_unavailable=true", body)
    n = res["hits"]["total"]["value"]
    agg = res["aggregations"]
    print(f"{n:,} {a.os} events {scope_text(a)} match: "
          f"{'children of ' if a.descendants else ''}{conditions_text(entries)}")
    if a.descendants:
        print("  (direct children only; deeper descendants would be filtered too)")
    for name, key in (("hosts", "hosts"), ("categories", "cat")):
        if agg[key]["buckets"]:
            print(f"  {name}: " + ", ".join(f"{b['key']} {b['doc_count']:,}" for b in agg[key]["buckets"]))


def add_filter(api, a):
    entries = parse_conditions(a)
    why = conditions_risk(entries, a.descendants)
    if why and not a.force:
        sys.exit(f"Refusing: {why}.\nAdd a narrower condition, or --allow NAME if that program is fine to "
                 f"filter here (see safety.json), or pass --force if you really mean it.")
    tags = [DESCENDANTS_TAG] if a.descendants else []
    item = make_item(a, a.os, entries, tags, a.note or "")
    print(describe_item(item))
    if why:
        print(f"  WARNING: {why}")
    if a.dry_run:
        print(json.dumps(item, indent=2))
    create_items(api, a, [item])


def all_filters(api, soft=False):
    """All event filters, or None if soft and this key can't read them."""
    items, page = [], 1
    while True:
        q = urllib.parse.urlencode({"list_id": EVENT_FILTERS_LIST, "namespace_type": "agnostic",
                                    "per_page": 100, "page": page, "sort_field": "created_at", "sort_order": "asc"})
        res = api.kb("GET", f"/api/exception_lists/items/_find?{q}", ok404=not soft, soft=soft)
        if res is None and soft:
            return None
        if not res:
            return items
        items += res["data"]
        if len(items) >= res["total"] or not res["data"]:
            return items
        page += 1


def show_rules(api):
    items = all_filters(api)
    save_record(items)
    if not items:
        print("No event filters yet.")
        return
    for it in items:
        mine = "" if it["item_id"].startswith(OWN_PREFIXES) else "   (not made by this script)"
        print(f"\n{it['item_id']}{mine}\n  created: {it['created_at'][:16]} by {it.get('created_by', '?')}")
        print(describe_item(it))


def delete_rule(api, a):
    q = urllib.parse.urlencode({"item_id": a.delete_rule, "namespace_type": "agnostic"})
    item = api.kb("GET", f"/api/exception_lists/items?{q}", ok404=True)
    if item is None:
        sys.exit(f"No event filter with item_id {a.delete_rule} (see --list-filters).")
    print(describe_item(item))
    if not a.yes:
        if not sys.stdin.isatty():
            sys.exit("Not a terminal; re-run with --yes to delete it.")
        if input("Delete this event filter? [y/N] ").strip().lower() not in ("y", "yes"):
            sys.exit("Nothing deleted.")
    api.kb("DELETE", f"/api/exception_lists/items?{q}")
    print(f"deleted: {a.delete_rule}")


def show_policies(api):
    q = urllib.parse.urlencode({"kuery": "ingest-package-policies.package.name:endpoint", "perPage": 100})
    pols = api.kb("GET", f"/api/fleet/package_policies?{q}")["items"]
    agents = api.kb("GET", "/api/fleet/agents?perPage=1000")["items"]
    for p in pols:
        hosts = sorted(ag["local_metadata"]["host"]["hostname"] for ag in agents
                       if ag.get("policy_id") in (p.get("policy_ids") or [p.get("policy_id")]))
        print(f"{p['id']}  {p['name']}\n    hosts: {', '.join(hosts) or '-'}")
    print("\nUse: noise-cut.py --ignore-rule N --policy ID   (by-policy filters may need a higher license)")


# ---------------------------------------------------------------- breakdown

def breakdown(api, a):
    if a.descendants:
        # Break down the direct children: --term process.X becomes process.parent.X (like --count).
        if not a.term:
            sys.exit("--breakdown --descendants needs --term process.FIELD=VALUE for the parent")
        for t in a.term:
            if not t.startswith("process.") or t.startswith("process.parent."):
                sys.exit(f"--breakdown --descendants only understands process.* terms, not {t.split('=', 1)[0]}")
        a.term = ["process.parent." + t[8:] for t in a.term]
    fields = a.field or DEFAULT_FIELDS
    aggs = {f: {"terms": {"field": f, "size": a.top}} for f in fields}
    if a.pairs:
        outer, inner = a.pairs.split(",")
        aggs["_pairs"] = {"terms": {"field": outer, "size": a.top},
                          "aggs": {"inner": {"terms": {"field": inner, "size": 5}}}}

    body = {"size": 0, "track_total_hits": True, "query": base_query(a), "aggs": aggs}
    res = api.es(f"/{a.index}/_search?ignore_unavailable=true", body)
    total = res["hits"]["total"]["value"]
    print(f"{total:,} docs in {a.index} {scope_text(a)}")
    if a.descendants:
        print("  (direct children only; deeper descendants would be filtered too)")
    if not total:
        return

    for f in fields:
        agg = res["aggregations"][f]
        buckets = agg["buckets"]
        if not buckets:
            continue
        covered = sum(b["doc_count"] for b in buckets) + agg["sum_other_doc_count"]
        print(f"\n== {f}  ({covered / total:.0%} of docs have it)")
        for b in buckets:
            print(f"{b['doc_count']:>14,}  {b['doc_count'] / total:6.1%}  {b['key']}")
        if agg["sum_other_doc_count"]:
            print(f"{agg['sum_other_doc_count']:>14,}  {agg['sum_other_doc_count'] / total:6.1%}  (other)")

    if a.pairs:
        print(f"\n== {outer} -> top {inner}")
        for b in res["aggregations"]["_pairs"]["buckets"]:
            print(f"{b['doc_count']:>14,}  {b['doc_count'] / total:6.1%}  {b['key']}")
            for c in b["inner"]["buckets"]:
                print(f"{'':>14}  {c['doc_count']:>12,}  {c['key']}")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
                                allow_abbrev=False)
    p.add_argument("--since", default="24h", help="time window, e.g. 1h, 24h, 7d (default 24h)")
    p.add_argument("--env-file", help="settings file (default config/user.env)")
    p.add_argument("--index", default="logs-*", help="index pattern (default logs-*)")
    p.add_argument("--host", help="only count events with this host.name")
    p.add_argument("--term", action="append", default=[], metavar="FIELD=VALUE",
                   help="only count events where FIELD is VALUE; * and ? in VALUE are wildcards (repeatable)")
    p.add_argument("--top", type=int, default=10, help="rules to propose (default 10)")
    p.add_argument("--json", action="store_true", help="print the candidate list as JSON")

    g = p.add_argument_group("event filters")
    g.add_argument("--ignore-rule", action="append", metavar="N[,N|N-M...]",
                   help="create Defend event filters from rows of the last list, e.g. 3,5,8-10")
    g.add_argument("--add-filter", action="store_true", help="create a filter from --os/--match/--wildcard")
    g.add_argument("--count", action="store_true", help="count events matching --os/--match/--wildcard")
    g.add_argument("--os", help="linux, macos or windows (with --add-filter/--count)")
    g.add_argument("--match", action="append", metavar="FIELD=VALUE", help="exact condition (repeatable)")
    g.add_argument("--wildcard", action="append", metavar="FIELD=PATTERN",
                   help="* / ? pattern condition, e.g. for version numbers in paths (repeatable)")
    g.add_argument("--descendants", action="store_true",
                   help="Process Descendants filter: keep the matched process, drop what it starts")
    g.add_argument("--note", help="why this filter exists (stored in its description)")
    g.add_argument("--policy", action="append", metavar="ID",
                   help="scope new filters to this Defend integration policy instead of all (repeatable)")
    g.add_argument("--dry-run", action="store_true", help="with --ignore-rule: print the API body, create nothing")
    g.add_argument("--yes", "-y", action="store_true", help="don't ask before creating/deleting")
    g.add_argument("--force", action="store_true", help="allow rows marked ! (very broad filters)")
    g.add_argument("--allow", action="append", default=[], metavar="NAME",
                   help="treat this program (or path prefix) as safe to filter for this run, e.g. --allow cron "
                   "(repeatable; to make it permanent, add it to \"allow\" in safety.local.json)")
    g.add_argument("--list-filters", "--rules", dest="rules", action="store_true", help="list existing event filters")
    g.add_argument("--delete-rule", metavar="ITEM_ID", help="delete an event filter by item_id")
    g.add_argument("--policies", action="store_true", help="list Defend policies and their hosts")

    b = p.add_argument_group("plain breakdown")
    b.add_argument("--breakdown", action="store_true", help="counts per field instead of filter candidates")
    b.add_argument("--field", action="append", help="field to break down by (repeatable; replaces defaults)")
    b.add_argument("--pairs", default="data_stream.dataset,process.name",
                   help="two fields to cross-tabulate (default data_stream.dataset,process.name; '' to skip)")
    a = p.parse_args()
    load_safety(a.allow)
    init_state()
    if a.env_file:
        os.environ["ELASTIC_ENV_FILE"] = a.env_file
    api = Api()

    if a.ignore_rule:
        ignore_rules(api, a)
    elif a.add_filter:
        add_filter(api, a)
    elif a.count:
        count_conditions(api, a)
    elif a.rules:
        show_rules(api)
    elif a.delete_rule:
        delete_rule(api, a)
    elif a.policies:
        show_policies(api)
    elif a.breakdown or a.field:
        breakdown(api, a)
    else:
        show_candidates(api, a)


if __name__ == "__main__":
    main()
