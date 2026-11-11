#!/usr/bin/env python3
r"""Ingest, filter savings and billing metrics -> InfluxDB, for the Grafana dashboard in grafana/.

  noise-metrics.py                   last 2 complete days, filter effects, last 3 billed days -> InfluxDB
                                     (90 billed days while InfluxDB holds none)
  noise-metrics.py --days 30 --billing-days 90    backfill what Elasticsearch holds and 90 billed days
  noise-metrics.py --print           the same, as line protocol on stdout; writes nothing
  noise-metrics.py --verify          read back what InfluxDB holds, per measurement
  noise-metrics.py --push-dashboard  push grafana/noise-cut-dashboard.json and query every panel

Every Elastic Defend event filter is listed from Kibana and turned into a search. An event filter drops
events on the endpoint, so after creation its count should fall to ~0: saved/day is the baseline (events/day
before creation) less what still matches. GB/day comes from the stream's average _source size, scaled to the
bill; $/month from the ingest rate on the Elastic Cloud bill. Every point has a fixed timestamp (a day, a run)
or is a snapshot at now, so running it again overwrites, never double counts.

Elastic: one read-only key, checked before use: config/read.env (searches logs-*, lists event filters with GET).
Elastic Cloud: EC_API_KEY, GET only. Settings in --env-file (config/metrics.env): ELASTIC_URL,
INFLUXDB_URL, INFLUXDB_ORG_ID, INFLUXDB_BUCKET, INFLUXDB_API_KEY, INFLUXDB_CA_FILE or INFLUXDB_CERT_SHA256,
EC_API_KEY, ECU_USD, and GRAFANA_* for --push-dashboard.
"""
import argparse
import csv
import datetime
import glob
import hashlib
import http.client
import io
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)  # the repo: es_read, noise_rules; the agent's noise_gate for filter queries
sys.path[:0] = [HERE, ROOT, os.path.join(ROOT, "agent")]
import noise_gate as ng  # noqa: E402
import noise_rules as nr  # noqa: E402
from es_read import Search  # noqa: E402

METRICS_ENV = os.path.join(HERE, "config", "metrics.env")
READ_KEY = os.path.join(HERE, "config", "read.env")  # read-only: searches logs-* and lists event filters
DASHBOARD = os.path.join(HERE, "grafana", "noise-cut-dashboard.json")
RUNS = os.environ.get("NOISE_OUT") or os.path.join(ROOT, "agent", "runs")  # the agent's runs: dry-run "would save"
DIMS = {"host": ("host.name", 100), "dataset": ("data_stream.dataset", 100), "category": ("event.category", 30)}
MAJOR_SHARE = 0.05   # datasets with this share of events decide which days are still fully stored
MEASUREMENTS = ("ingest_daily", "ingest_24h", "ingest_store", "noise_run", "noise_filter_effect",
                "noise_filter_baseline", "noise_savings_total", "elastic_billing")
DAY = 86400
EVENT_FILTERS_LIST = "endpoint_event_filters"
DESCENDANTS_TAG = "filter_process_descendants"
AGENT_MARKER = "noise-agent:"                       # noise-pipeline.py MARKER
SCRIPT_MARKER = re.compile(r"^Added by (?:noise-cut|elastic-noise)\.py ")  # noise-cut.py make_item (and its old name)
SCRIPT_ITEM_PREFIX = ("noise-cut-", "elastic-noise-")
# noise-cut.py writes what a filter matched when it was made: "... 12,345 events over the last 24h ..."
SCRIPT_COUNT = re.compile(r"^Added by (?:noise-cut|elastic-noise)\.py [\d-]+\. ([\d,]+) events over the last (\d+[smhdw])\b")
WORKING_SHARE = 0.05  # still matching under 5% of the baseline: working
LEAK_SHARE = 0.75     # still matching 75% or more: the filter doesn't take effect
STRAY_PER_DAY = 1.0   # without a baseline, under one event/day is a stray event, not a leak
SAMPLE_DOCS = 200     # docs read to measure a stream's average _source size
CLOUD_API = "https://api.elastic-cloud.com"
BILLING_MAX_DAYS = 90   # billing backfill cap: one API request per day
LOOKBACK_DAYS = 365     # how far back InfluxDB is read for stored baselines and billing


# ---------------------------------------------------------------- line protocol

def _esc(s, chars):
    s = re.sub(r"[\x00-\x1f\x7f]", " ", str(s))
    for c in "\\" + chars:
        s = s.replace(c, "\\" + c)
    return s


def line(measurement, tags, fields, ts):
    """One InfluxDB line. Empty tags are left out; ints get an i, strings are quoted."""
    t = "".join(f",{_esc(k, ',= ')}={_esc(v, ',= ')}" for k, v in sorted(tags.items()) if str(v) != "")
    fs = []
    for k, v in fields.items():
        if v is None:
            continue
        if isinstance(v, bool):
            v = "true" if v else "false"
        elif isinstance(v, int):
            v = f"{v}i"
        elif isinstance(v, float):
            v = repr(v)
        else:
            v = '"' + _esc(v, '"') + '"'
        fs.append(f"{_esc(k, ',= ')}={v}")
    return f"{_esc(measurement, ', ')}{t} {','.join(fs)} {int(ts)}"


def epoch(iso):
    return int(datetime.datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp())


# ---------------------------------------------------------------- Elasticsearch

def complete_from(search):
    """Epoch seconds from which every major dataset is still fully stored: days before it have partly
    expired, so their counts would show retention, not ingest."""
    res = search.search({"size": 0, "query": {"range": {"@timestamp": {"lt": "now"}}},
                         "aggs": {"ds": {"terms": {"field": "data_stream.dataset", "size": 100},
                                         "aggs": {"first": {"min": {"field": "@timestamp"}}}}}})
    buckets = res["aggregations"]["ds"]["buckets"]
    total = sum(b["doc_count"] for b in buckets) or 1
    firsts = [b["first"]["value"] for b in buckets if b["doc_count"] >= MAJOR_SHARE * total and b["first"]["value"]]
    return int(max(firsts) / 1000) if firsts else 0


def daily(search, days, since):
    """ingest_daily points for the complete days of the last `days`, from `since` (complete_from) on."""
    aggs = {d: {"terms": {"field": f, "size": n}} for d, (f, n) in DIMS.items()}
    res = search.search({"size": 0, "query": {"range": {"@timestamp": {"gte": f"now-{days}d/d", "lt": "now/d"}}},
                         "aggs": {"d": {"date_histogram": {"field": "@timestamp", "calendar_interval": "1d",
                                                           "time_zone": "UTC", "min_doc_count": 0},
                                        "aggs": aggs}}})
    lines, kept, skipped = [], 0, 0
    for b in res["aggregations"]["d"]["buckets"]:
        ts = int(b["key"] / 1000)
        if ts < since:
            skipped += 1
            continue
        kept += 1
        lines.append(line("ingest_daily", {"dim": "total", "key": "all"}, {"events": b["doc_count"]}, ts))
        for d in DIMS:
            for x in b[d]["buckets"]:
                lines.append(line("ingest_daily", {"dim": d, "key": x["key"]}, {"events": x["doc_count"]}, ts))
            if b[d].get("sum_other_doc_count"):
                lines.append(line("ingest_daily", {"dim": d, "key": "(other)"},
                                  {"events": b[d]["sum_other_doc_count"]}, ts))
    return lines, kept, skipped


def last_24h(search, now):
    res = search.search({"size": 0, "track_total_hits": True, "query": {"range": {"@timestamp": {"gte": "now-24h"}}},
                         "aggs": {"ds": {"terms": {"field": "data_stream.dataset", "size": 100}}}})
    total = res["hits"]["total"]["value"]
    out = [line("ingest_24h", {"dim": "total", "key": "all"}, {"events": total}, now)]
    out += [line("ingest_24h", {"dim": "dataset", "key": b["key"]}, {"events": b["doc_count"]}, now)
            for b in res["aggregations"]["ds"]["buckets"]]
    return out, total


def store_stats(search, now):
    """Bytes stored per index, if this key may read index stats (not on serverless, not with a key
    restricted to read): ([lines], why not)."""
    req = urllib.request.Request(search.url + "/logs-*/_stats/store,docs?level=indices",
                                 headers={"Authorization": f"ApiKey {search._key}"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            res = json.load(r)
    except urllib.error.HTTPError as e:
        return [], f"HTTP {e.code}"
    except (urllib.error.URLError, OSError, ValueError) as e:
        return [], str(e)[:100]
    out = []
    for name, ix in (res.get("indices") or {}).items():
        p = ix.get("primaries") or {}
        out.append(line("ingest_store", {"index": re.sub(r"^\.ds-|-\d{4}\.\d{2}\.\d{2}-\d+$", "", name)},
                        {"bytes": int((p.get("store") or {}).get("size_in_bytes", 0)),
                         "docs": int((p.get("docs") or {}).get("count", 0))}, now))
    return out, ""


# ---------------------------------------------------------------- run folders

def load_json(path):
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def run_time(folder):
    m = re.search(r"run-(\d{8}T\d{6}Z)$", folder)
    return int(datetime.datetime.strptime(m.group(1), "%Y%m%dT%H%M%SZ").replace(
        tzinfo=datetime.timezone.utc).timestamp()) if m else None


def runs(runs_dir):
    """noise_run points (what each run created, or would have in a dry run), and per filter an apply run
    created: {fingerprint: events/day it matched then}, a baseline for filters made by noise-agent."""
    lines, created = [], {}
    for folder in sorted(glob.glob(os.path.join(runs_dir, "run-*"))):
        data = os.path.join(folder, "data")
        rows, props = load_json(os.path.join(data, "rows.json")), load_json(os.path.join(data, "proposals.json"))
        applied = load_json(os.path.join(data, "applied.json"))
        ts = epoch(applied["created"]) if applied and applied.get("created") else run_time(folder)
        if ts is None:
            continue
        mode = "incomplete" if not applied else "dry_run" if applied.get("dry_run") else "apply"
        made = [c for c in (applied or {}).get("filters", []) if c.get("ok")]
        filters = (props or {}).get("filters", [])
        f = {"run": os.path.basename(folder),
             "total_events": (props or rows or {}).get("total"),
             "rows": len((rows or {}).get("proposals", [])), "rows_not_proposed": len((rows or {}).get("skipped", [])),
             "rows_events": sum(r.get("count", 0) for r in (rows or {}).get("proposals", [])),
             "proposed": len(filters), "gate_ok": sum(bool((x.get("gate") or {}).get("ok")) for x in filters),
             "proposed_events": sum((x.get("gate") or {}).get("events", 0) for x in filters
                                    if (x.get("gate") or {}).get("ok")),
             "created": len(made), "save_events": sum(c.get("events", 0) for c in made),
             "rejected": len((applied or {}).get("rejected", [])),
             "overlapping": len((applied or {}).get("overlapping", [])),
             "suggestions": len((props or {}).get("suggestions", [])),
             "fix_at_source": len((props or {}).get("fix_at_source", [])),
             "tokens_in": (props or {}).get("tokens_in"), "tokens_out": (props or {}).get("tokens_out"),
             "propose_seconds": (props or {}).get("seconds")}
        f = {k: v if k == "run" or v is None else int(v) for k, v in f.items()}  # one type per field, always
        lines.append(line("noise_run", {"mode": mode}, f, ts))
        if mode == "apply":
            window = nr.window_seconds((props or {}).get("since", "24h")) or DAY
            for c in made:
                if c.get("fingerprint"):
                    created[c["fingerprint"]] = c.get("events", 0) * DAY / window
    return lines, created


# ---------------------------------------------------------------- event filters (Kibana, read-only)

def kibana_url(conf):
    url = (conf.get("KIBANA_URL") or conf.get("ELASTIC_URL", "").replace(".es.", ".kb.", 1)).rstrip("/")
    if not url.startswith("https://"):
        sys.exit("Set ELASTIC_URL (https://...) or KIBANA_URL in the settings file.")
    return url


def event_filters(search, conf):
    """Every Elastic Defend event filter (all pages), with the read-only key `search` holds. GET only."""
    items, page = [], 1
    while True:
        q = urllib.parse.urlencode({"list_id": EVENT_FILTERS_LIST, "namespace_type": "agnostic", "per_page": 100,
                                    "page": page, "sort_field": "created_at", "sort_order": "asc"})
        req = urllib.request.Request(f"{kibana_url(conf)}/api/exception_lists/items/_find?{q}", method="GET",
                                     headers={"Authorization": f"ApiKey {search._key}",
                                              "elastic-api-version": "2023-10-31"})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                res = json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return items  # no event filter list yet
            sys.exit(f"Kibana HTTP {e.code} listing event filters with {search.key_from}: "
                     f"{e.read().decode(errors='replace')[:300]}")
        items += res.get("data") or []
        if len(items) >= res.get("total", 0) or not res.get("data"):
            return items
        page += 1


def source(item):
    """Who made it: noise-agent, noise-cut.py or manual (by the markers each writes)."""
    desc = item.get("description") or ""
    if AGENT_MARKER in desc:
        return "noise-agent"
    if SCRIPT_MARKER.match(desc) or str(item.get("item_id", "")).startswith(SCRIPT_ITEM_PREFIX):
        return "noise-cut.py"
    return "manual"


def item_fingerprint(item):
    """noise_gate.fingerprint() of the filter a Kibana item holds, to find it in the run folders."""
    c = {"os": (item.get("os_types") or [""])[0], "descendants": DESCENDANTS_TAG in (item.get("tags") or []),
         "conditions": [{"field": e.get("field"), "value": e.get("value")} for e in item.get("entries") or []]}
    return hashlib.sha256(json.dumps(c, sort_keys=True).encode()).hexdigest()


def description_baseline(item):
    """Events/day noise-cut.py counted when it made this filter (from its description), or None."""
    m = SCRIPT_COUNT.match(item.get("description") or "")
    if not m:
        return None
    return int(m.group(1).replace(",", "")) * DAY / nr.window_seconds(m.group(2))


class Untranslatable(ValueError):
    pass


def entry_clause(e, field_prefix="", windows=False):
    """One event filter entry as (bool occurrence, Elasticsearch query). Raises Untranslatable."""
    t, field, v = e.get("type"), field_prefix + str(e.get("field") or ""), e.get("value")
    if not field or field == field_prefix:
        raise Untranslatable("an entry without a field")
    ci = field.endswith(".caseless") or windows  # Defend's .caseless fields; Windows paths ignore case
    field = field.removesuffix(".caseless")
    opts = {"case_insensitive": True} if ci else {}
    if t == "match" and isinstance(v, str):
        q = {"term": {field: {"value": v, **opts}}}
    elif t == "match_any" and isinstance(v, list) and v and all(isinstance(x, str) for x in v):
        q = ({"bool": {"minimum_should_match": 1, "should": [{"term": {field: {"value": x, **opts}}} for x in v]}}
             if ci else {"terms": {field: v}})
    elif t == "wildcard" and isinstance(v, str):
        q = {"wildcard": {field: {"value": v.replace("\\", "\\\\"), **opts}}}
    elif t == "exists":
        q = {"exists": {"field": field}}
    elif t == "nested" and e.get("entries"):
        # Defend matches nested entries within one object of an array; this matches them anywhere in it.
        subs = [entry_clause(x, field + ".", windows) for x in e["entries"]]
        q = {"bool": {occ: [c for o, c in subs if o == occ] for occ in ("filter", "must_not")
                      if any(o == occ for o, _ in subs)}}
    else:
        raise Untranslatable(f"{t or 'unknown'} entry on {field} (value lists and the like can't be searched)")
    return ("must_not" if e.get("operator") == "excluded" else "filter"), q


def filter_query(item):
    """(Elasticsearch query for the events this filter drops, "exact" or "approx"). Raises Untranslatable.
    Descendants filters match the process' direct children (process.parent.*): grandchildren are missed."""
    entries, os_types = item.get("entries") or [], item.get("os_types") or []
    if not entries:
        raise Untranslatable("no entries")
    desc = DESCENDANTS_TAG in (item.get("tags") or [])
    windows = os_types == ["windows"]
    q = {"filter": [], "must_not": []}
    if os_types:
        q["filter"].append({"terms": {"host.os.type": os_types}})
    approx = desc
    for e in entries:
        field = str(e.get("field") or "")
        if desc:
            if not field.startswith("process.") or field.startswith("process.parent."):
                raise Untranslatable(f"descendants filter on {field} (only process.* can be moved to the parent)")
            e = dict(e, field="process.parent." + field[len("process."):])
        approx = approx or e.get("type") == "nested"
        occ, clause = entry_clause(e, windows=windows)
        q[occ].append(clause)
    return {"bool": {k: v for k, v in q.items() if v}}, "approx" if approx else "exact"


def stream_query(item):
    """The stream a filter was made for, without its exact command line: the program (or the script a shell
    or interpreter runs) on the same OS and event.category. None when the filter has no command line or the
    program isn't a full path. A filter matching nothing while its stream still arrives has drifted: the
    command line changed (new arguments, a renamed script) and Defend no longer drops it."""
    entries, os_types = item.get("entries") or [], item.get("os_types") or []
    desc = DESCENDANTS_TAG in (item.get("tags") or [])
    cmd = next((e.get("value") for e in entries if e.get("field") == "process.command_line"
                and e.get("type") == "match" and e.get("operator") != "excluded"), None)
    if not isinstance(cmd, str):
        return None
    argv = nr.split_args(cmd)
    if not argv:
        return None
    prefix = "process.parent." if desc else "process."
    if nr.generic(nr.basename(argv[0])):
        script = next((a for a in argv[1:] if not a.startswith(("-", "+"))), "")
        if not script.startswith("/"):
            return None
        clause = {"wildcard": {prefix + "command_line": {"value": "*" + script.replace("\\", "\\\\") + "*"}}}
    elif argv[0].startswith("/"):
        clause = {"term": {prefix + "executable": {"value": argv[0]}}}
    else:
        return None
    f = [clause] + ([{"terms": {"host.os.type": os_types}}] if os_types else [])
    cat = filter_category(item)
    f += [{"term": {"event.category": cat}}] if cat else []
    return {"bool": {"filter": f}}


def drifted(r, s):
    """True when a filter looks like it works (r) but its stream (s, from stream_query) didn't drop."""
    if r["status"] != "working" or s["current"] is None or not r["baseline"]:
        return False
    if s["baseline_source"] == "window":  # the stream before and after the filter was made
        return s["baseline"] - s["current"] < (1 - LEAK_SHARE) * r["baseline"]
    return s["current"] >= LEAK_SHARE * r["baseline"]  # no stream before: still as big as what it hid


def daily_matches(search, queries, start, end, chunk=20):
    """{filter id: {UTC day epoch: events}} for each query, over complete days [start, end)."""
    out = {}
    ids = list(queries)
    for i in range(0, len(ids), chunk):
        part = {k: queries[k] for k in ids[i:i + chunk]}
        res = search.search({"size": 0, "query": {"range": {"@timestamp": {"gte": start * 1000, "lt": end * 1000,
                                                                           "format": "epoch_millis"}}},
                             "aggs": {"f": {"filters": {"filters": part}, "aggs": {"d": {"date_histogram": {
                                 "field": "@timestamp", "calendar_interval": "1d", "time_zone": "UTC",
                                 "min_doc_count": 0, "extended_bounds": {"min": start * 1000,
                                                                         "max": (end - DAY) * 1000}}}}}}})
        for k, b in res["aggregations"]["f"]["buckets"].items():
            out[k] = {int(d["key"] / 1000): d["doc_count"] for d in b["d"]["buckets"]
                      if start <= d["key"] / 1000 < end}
    return out


def avg(xs):
    return sum(xs) / len(xs) if xs else None


def status(baseline, current):
    if current is None:
        return "too new"  # no complete day since it was made
    if not baseline:
        return "not matching" if current < STRAY_PER_DAY else "leaking"
    if current < WORKING_SHARE * baseline:
        return "working"
    return "leaking" if current >= LEAK_SHARE * baseline else "partial"


def effect(days, created, stored=None, fallback=None):
    """A filter's effect from its matches per complete day ({day epoch: events}).
    Made inside those days: baseline = average/day before its creation day, current = average/day after.
    Made before: current = average/day; baseline = stored (InfluxDB, first seen) or fallback (run folder,
    description), else unknown. stored and fallback are (events/day, source)."""
    cday = created - created % DAY
    if days and cday >= min(days):
        before, after = [n for d, n in days.items() if d < cday], [n for d, n in days.items() if d > cday]
        current = avg(after)
        base = (avg(before), "window", len(before)) if before else None
    else:
        current, base = avg(list(days.values())), None
    if base is None:
        b = stored or fallback
        base = (b[0], b[1], 0) if b and b[0] is not None else (None, "unknown", 0)
    baseline, src, before_days = base
    saved = max(baseline - current, 0.0) if baseline is not None and current is not None else 0.0
    return {"baseline": baseline, "baseline_source": src, "baseline_days": before_days, "current": current,
            "saved": saved, "status": status(baseline, current),
            "after_days": len([d for d in days if d > cday]) if days and cday >= min(days) else len(days)}


def source_size(search, query, size=SAMPLE_DOCS):
    """(average _source JSON bytes, docs read) over up to `size` random docs matching query."""
    res = search.search({"size": size, "query": {"function_score": {"query": query, "boost_mode": "replace",
                                                                    "random_score": {"seed": 7, "field": "_seq_no"}}}})
    sizes = [len(json.dumps(h.get("_source", {}), separators=(",", ":"))) for h in res["hits"]["hits"]]
    return (sum(sizes) / len(sizes), len(sizes)) if sizes else (None, 0)


def filter_category(item):
    for e in item.get("entries") or []:
        if e.get("field") == "event.category" and e.get("type") == "match" and DESCENDANTS_TAG not in item.get("tags", []):
            return e["value"]
    return ""


def filter_effects(search, items, start, end, now, stored, run_baselines, cost):
    """noise_filter_effect points, one per event filter, and new noise_filter_baseline points.
    stored: {filter id: (events/day, source)} from InfluxDB. cost: per_gb(avg bytes) -> (GB per event, $/GB)."""
    queries, rows = {}, []
    for it in items:
        try:
            q, how = filter_query(it)
            queries[it["id"]] = q
            rows.append((it, q, how, ""))
        except Untranslatable as e:
            rows.append((it, None, "untranslatable", str(e)))
    matches = daily_matches(search, queries, start, end) if queries and end > start else {}
    streams = {it["id"]: stream_query(it) for it, q, _, _ in rows if q is not None}
    streams = {k: v for k, v in streams.items() if v}
    stream_matches = daily_matches(search, streams, start, end) if streams and end > start else {}
    fallback_size = {}
    lines, baselines, results = [], [], []
    for it, q, how, why in rows:
        fid, created = it["id"], epoch(it["created_at"])
        r = {"status": "untranslatable", "baseline": None, "baseline_source": "unknown", "baseline_days": 0,
             "current": None, "saved": 0.0, "after_days": 0}
        avg_bytes, size_from = None, ""
        if q is not None:
            fallback = run_baselines.get(item_fingerprint(it))
            fallback = (fallback, "run") if fallback is not None else (description_baseline(it), "description")
            r = effect(matches.get(fid, {}), created, stored.get(fid), fallback)
            if fid in stream_matches and drifted(r, effect(stream_matches[fid], created)):
                r.update(status="drifted", saved=0.0)
            if r["baseline_source"] in ("window", "run", "description") and fid not in stored:
                baselines.append(line("noise_filter_baseline", {"filter_id": fid},
                                      {"baseline_per_day": float(r["baseline"]), "source": r["baseline_source"],
                                       "days": r["baseline_days"], "name": it.get("name", "")[:200]}, now))
            if r["saved"] > 0 or r["current"]:
                # The stream's own docs: before creation if Elasticsearch still holds them, else what leaks now.
                when = {"lt": max(created, start) * 1000} if r["baseline_source"] == "window" else {"gte": start * 1000}
                avg_bytes, n = source_size(search, {"bool": {"filter": [q, {"range": {"@timestamp": dict(
                    when, format="epoch_millis")}}]}})
                size_from = "sample" if n else ""
            if avg_bytes is None and r["saved"] > 0:
                key = ((it.get("os_types") or [""])[0], filter_category(it))
                if key not in fallback_size:
                    f = [{"range": {"@timestamp": {"gte": start * 1000, "format": "epoch_millis"}}}]
                    f += [{"term": {"host.os.type": key[0]}}] if key[0] else []
                    f += [{"term": {"event.category": key[1]}}] if key[1] else []
                    fallback_size[key] = source_size(search, {"bool": {"filter": f}})[0]
                avg_bytes, size_from = fallback_size[key], f"average {key[0] or 'all'} {key[1] or 'events'}"
        gb_per_event, usd_per_gb = cost(avg_bytes)
        gb_day = r["saved"] * gb_per_event if gb_per_event is not None else None
        usd_month = gb_day * 30 * usd_per_gb if gb_day is not None and usd_per_gb is not None else None
        r.update(id=fid, name=it.get("name", ""), source=source(it), os=",".join(it.get("os_types") or []),
                 gb_day=gb_day or 0.0, usd_month=usd_month or 0.0, avg_bytes=avg_bytes, translation=how)
        results.append(r)
        fields = {"current_per_day": None if r["current"] is None else float(r["current"]),
                  "baseline_per_day": None if r["baseline"] is None else float(r["baseline"]),
                  "saved_per_day": float(r["saved"]), "saved_gb_day": float(gb_day or 0.0),
                  "saved_usd_month": float(usd_month or 0.0),
                  "avg_bytes": None if avg_bytes is None else float(avg_bytes), "size_from": size_from,
                  "baseline_source": r["baseline_source"], "translation": how, "note": why[:200],
                  "created": it.get("created_at", "")[:10], "updated": it.get("updated_at", "")[:10],
                  "days_measured": r["after_days"], "descendants": DESCENDANTS_TAG in (it.get("tags") or []),
                  "entries": json.dumps(it.get("entries") or [], separators=(",", ":"))[:1000],
                  "tags": ",".join(it.get("tags") or [])[:300], "description": (it.get("description") or "")[:256]}
        lines.append(line("noise_filter_effect", {"filter_id": fid, "name": r["name"][:120], "source": r["source"],
                                                  "os": r["os"], "status": r["status"]}, fields, now))
    return lines, baselines, results


def totals(results, now, extra):
    """noise_savings_total: per source and for all filters, counts by status and the sums."""
    out = []
    for src in ["all"] + sorted({r["source"] for r in results}):
        rs = [r for r in results if src in ("all", r["source"])]
        f = {"filters": len(rs), "saved_per_day": float(sum(r["saved"] for r in rs)),
             "saved_gb_day": float(sum(r["gb_day"] for r in rs)),
             "saved_usd_month": float(sum(r["usd_month"] for r in rs)),
             "baseline_unknown": sum(r["baseline_source"] == "unknown" for r in rs)}
        for st in ("working", "partial", "leaking", "drifted", "not matching", "untranslatable", "too new"):
            f[st.replace(" ", "_")] = sum(r["status"] == st for r in rs)
        out.append(line("noise_savings_total", {"source": src}, dict(f, **extra), now))
    return out


# ---------------------------------------------------------------- Elastic Cloud billing (GET only)

class Cloud:
    def __init__(self, conf):
        self.url = conf.get("EC_API_URL", CLOUD_API).rstrip("/")
        self._key = conf.get("EC_API_KEY", "")
        if not self.url.startswith("https://") or not self._key:
            raise ValueError("no EC_API_KEY (or EC_API_URL is not https://)")

    def get(self, path):
        req = urllib.request.Request(self.url + path, method="GET", headers={"Authorization": f"ApiKey {self._key}"})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            raise ValueError(f"Elastic Cloud HTTP {e.code} on GET {path.split('?')[0]}: "
                             f"{e.read().decode(errors='replace')[:200]}") from None
        except (urllib.error.URLError, OSError) as e:
            raise ValueError(f"Elastic Cloud: {e}") from None


def billing_fields(res, ecu_usd):
    """A day's cost items as elastic_billing fields: total, ingest and retention (GB, rate, ECU)."""
    f = {"total_ecu": float(res.get("total_ecu") or 0.0), "ingest_gb": 0.0, "ingest_ecu": 0.0,
         "retention_gb": 0.0, "retention_ecu": 0.0, "other_ecu": 0.0}
    rate = None
    for prod in res.get("products") or []:
        for it in prod.get("product_line_items") or []:
            name, ecu = it.get("name") or "", float(it.get("total_ecu") or 0.0)
            gb = float((it.get("quantity") or {}).get("value") or 0.0)
            if "Data ingestion" in name:
                f["ingest_gb"] += gb
                f["ingest_ecu"] += ecu
                rate = float((it.get("rate") or {}).get("value") or 0.0) or rate
            elif "Data retention" in name:
                f["retention_gb"] += gb
                f["retention_ecu"] += ecu
            else:
                f["other_ecu"] += ecu
    if rate is not None:
        f["ingest_rate"] = rate
    f["total_usd"] = f["total_ecu"] * ecu_usd
    return f


def billing(cloud, conf, days, today, ecu_usd):
    """elastic_billing points for the complete UTC days of the last `days` (one request per day), and the
    latest day's fields."""
    org = conf.get("EC_ORG_ID") or cloud.get("/api/v1/organizations")["organizations"][0]["id"]
    projects = cloud.get("/api/v1/serverless/projects/security").get("items") or []
    project = next((p for p in projects if p["id"] == conf.get("EC_PROJECT_ID")), None) if conf.get(
        "EC_PROJECT_ID") else (projects[0] if len(projects) == 1 else None)
    if not project:
        raise ValueError("set EC_PROJECT_ID: the key sees %d security projects" % len(projects))
    born = epoch(project.get("metadata", {}).get("created_at", "1970-01-01T00:00:00Z")[:19] + "+00:00")
    lines, latest = [], None
    for ts in range(today - min(days, BILLING_MAX_DAYS) * DAY, today, DAY):
        if ts + DAY <= born:
            continue
        frm, to = (datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                   for t in (ts, ts + DAY))
        res = cloud.get(f"/api/v2/billing/organizations/{org}/costs/instances/{project['id']}/items?from={frm}&to={to}")
        if not res.get("products"):
            continue
        f = billing_fields(res, ecu_usd)
        lines.append(line("elastic_billing", {}, f, ts))
        latest = dict(f, ts=ts)
    return lines, latest


# ---------------------------------------------------------------- InfluxDB

class Influx:
    """Writes and queries over HTTPS. A private CA (INFLUXDB_CA_FILE) is checked as usual; a pinned leaf
    (INFLUXDB_CERT_SHA256) is checked before the token is sent; neither: the system's CAs."""

    def __init__(self, conf, root=ROOT):
        self.url = conf.get("INFLUXDB_URL", "").rstrip("/")
        self.org, self.bucket = conf.get("INFLUXDB_ORG_ID", ""), conf.get("INFLUXDB_BUCKET", "noise-cut")
        self._token = conf.get("INFLUXDB_API_KEY", "")
        u = urllib.parse.urlsplit(self.url)
        if u.scheme != "https" or not u.hostname or not self.org or not self._token:
            sys.exit("Set INFLUXDB_URL (https://...), INFLUXDB_ORG_ID and INFLUXDB_API_KEY in the settings file.")
        self.host, self.port, self.base = u.hostname, u.port or 443, u.path.rstrip("/")
        self.pin = None
        ca = conf.get("INFLUXDB_CA_FILE", "")
        if ca:
            ca = ca if os.path.isabs(ca) else os.path.join(root, ca)
            if not os.path.exists(ca):
                sys.exit(f"INFLUXDB_CA_FILE {ca} not found.")
            self.ctx = ssl.create_default_context(cafile=ca)
        elif conf.get("INFLUXDB_CERT_SHA256"):
            self.pin = conf["INFLUXDB_CERT_SHA256"].replace(":", "").lower()
            if not re.fullmatch(r"[0-9a-f]{64}", self.pin):
                sys.exit("INFLUXDB_CERT_SHA256 must be the leaf certificate's SHA-256 (64 hex digits, : allowed).")
            # The chain can't be checked without the CA; the exact certificate is, below, before anything is sent.
            self.ctx = ssl.create_default_context()
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE
        else:
            self.ctx = ssl.create_default_context()

    def _request(self, method, path, body, headers):
        conn = http.client.HTTPSConnection(self.host, self.port, context=self.ctx, timeout=60)
        try:
            conn.connect()
            if self.pin:
                got = hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest()
                if got != self.pin:
                    sys.exit(f"InfluxDB certificate sha256 {got} is not INFLUXDB_CERT_SHA256: not sending anything.")
            conn.request(method, self.base + path, body=body,
                         headers={"Authorization": f"Token {self._token}", **headers})
            r = conn.getresponse()
            data = r.read()
        except (OSError, ssl.SSLError, http.client.HTTPException) as e:
            sys.exit(f"InfluxDB {self.host}: {e}")
        finally:
            conn.close()
        if r.status >= 300:
            sys.exit(f"InfluxDB HTTP {r.status} on {path.split('?')[0]}: {data.decode(errors='replace')[:300]}")
        return data

    def write(self, lines, batch=5000):
        q = urllib.parse.urlencode({"orgID": self.org, "bucket": self.bucket, "precision": "s"})
        for i in range(0, len(lines), batch):
            self._request("POST", f"/api/v2/write?{q}", "\n".join(lines[i:i + batch]).encode(),
                          {"Content-Type": "text/plain; charset=utf-8"})

    def query(self, flux):
        """Rows of a Flux query, as dicts."""
        data = self._request("POST", "/api/v2/query?" + urllib.parse.urlencode({"orgID": self.org}), flux.encode(),
                             {"Content-Type": "application/vnd.flux", "Accept": "application/csv"})
        rows = []
        for table in re.split(r"\r?\n\r?\n", data.decode()):
            rd = csv.DictReader(io.StringIO(table.strip()))
            rows += [r for r in rd if any(v for k, v in r.items() if k not in ("", "result", "table"))]
        return rows


def stored_baselines(influx):
    """{filter id: (events/day, source)}: the baseline recorded when each filter was first seen."""
    flux = (f'from(bucket: "{influx.bucket}") |> range(start: -{LOOKBACK_DAYS}d) '
            f'|> filter(fn: (r) => r._measurement == "noise_filter_baseline") '
            f'|> filter(fn: (r) => r._field == "baseline_per_day" or r._field == "source") |> first() '
            f'|> pivot(rowKey: ["filter_id"], columnKey: ["_field"], valueColumn: "_value")')
    return {r["filter_id"]: (float(r["baseline_per_day"]), r.get("source") or "stored")
            for r in influx.query(flux) if r.get("baseline_per_day")}


def stored_billing(influx):
    """The latest elastic_billing day InfluxDB holds, as fields (with ts), or None."""
    flux = (f'from(bucket: "{influx.bucket}") |> range(start: -{LOOKBACK_DAYS}d) '
            f'|> filter(fn: (r) => r._measurement == "elastic_billing") |> last() '
            f'|> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value") '
            f'|> group() |> sort(columns: ["_time"], desc: true) |> limit(n: 1)')
    rows = influx.query(flux)
    if not rows:
        return None
    r = rows[0]
    out = {k: float(v) for k, v in r.items() if k.endswith(("_gb", "_ecu", "_rate", "_usd")) and v not in ("", None)}
    return dict(out, ts=epoch(r["_time"][:19] + "+00:00"))


def calibration(search, bill, day_events):
    """Billed bytes per event over average _source bytes per event, on the latest billed day Elasticsearch
    holds in full ({day epoch: events}): turns a stream's sampled size into what it costs. 1.0 if unknown."""
    if not bill or not bill.get("ingest_gb") or not day_events.get(bill["ts"]):
        return 1.0, None, None
    size, _ = source_size(search, {"range": {"@timestamp": {"gte": bill["ts"] * 1000, "lt": (bill["ts"] + DAY) * 1000,
                                                            "format": "epoch_millis"}}}, 500)
    billed = bill["ingest_gb"] * 1e9 / day_events[bill["ts"]]
    return (billed / size, billed, size) if size else (1.0, billed, None)


def total_per_day(search, start, end):
    res = search.search({"size": 0, "query": {"range": {"@timestamp": {"gte": start * 1000, "lt": end * 1000,
                                                                       "format": "epoch_millis"}}},
                         "aggs": {"d": {"date_histogram": {"field": "@timestamp", "calendar_interval": "1d",
                                                           "time_zone": "UTC"}}}})
    return {int(b["key"] / 1000): b["doc_count"] for b in res["aggregations"]["d"]["buckets"]}


# ---------------------------------------------------------------- Grafana

def grafana_request(conf, method, path, body=None):
    url = conf.get("GRAFANA_URL", "").rstrip("/")
    if not url.startswith("https://") or not conf.get("GRAFANA_API_KEY"):
        sys.exit("Set GRAFANA_URL (https://...) and GRAFANA_API_KEY in the settings file.")
    ca = conf.get("GRAFANA_CA_FILE") or conf.get("INFLUXDB_CA_FILE")
    if ca:
        ca = ca if os.path.isabs(ca) else os.path.join(ROOT, ca)
        if not os.path.exists(ca):
            sys.exit(f"CA file {ca} not found.")
    ctx = ssl.create_default_context(cafile=ca or None)
    req = urllib.request.Request(url + path, method=method, data=None if body is None else json.dumps(body).encode(),
                                 headers={"Authorization": f"Bearer {conf['GRAFANA_API_KEY']}",
                                          "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60, context=ctx) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}: {e.read().decode(errors='replace')[:300]}"}
    except (urllib.error.URLError, OSError) as e:
        sys.exit(f"Grafana: {e}")


def dashboard_for(conf, path=DASHBOARD):
    """The dashboard JSON with the import input replaced by GRAFANA_DATASOURCE_UID, the uid set and the
    bucket variable set to INFLUXDB_BUCKET (so panels read the bucket the metrics are written to)."""
    ds, uid = conf.get("GRAFANA_DATASOURCE_UID", ""), conf.get("GRAFANA_DASHBOARD_UID", "")
    if not ds:
        sys.exit("Set GRAFANA_DATASOURCE_UID (the InfluxDB Flux data source) in the settings file.")
    with open(path) as fh:
        d = json.loads(fh.read().replace("${DS_INFLUXDB}", ds))
    for k in ("__inputs", "__requires", "id"):
        d.pop(k, None)
    if uid:
        d["uid"] = uid
    bucket = conf.get("INFLUXDB_BUCKET", "noise-cut")
    for v in d.get("templating", {}).get("list", []):
        if v.get("name") == "bucket":
            v["query"], v["current"] = bucket, {"text": bucket, "value": bucket}
    return d


def frame_summary(frames):
    """A short text of what a panel query returned: rows, and the first values."""
    if not frames:
        return "no data"
    out = []
    for fr in frames[:3]:
        names = [f.get("name") for f in fr.get("schema", {}).get("fields", [])]
        vals = fr.get("data", {}).get("values", [])
        n = len(vals[0]) if vals else 0
        last = {nm: v[-1] for nm, v in zip(names, vals) if v and nm not in ("_time", "_start", "_stop")}
        lbl = next((f.get("labels") for f in fr.get("schema", {}).get("fields", []) if f.get("labels")), None)
        out.append(f"{n} rows" + (f" {lbl}" if lbl else "") + f" last {json.dumps(last, default=str)[:160]}")
    return f"{len(frames)} frames; " + " | ".join(out)


def push_dashboard(conf, bucket):
    d = dashboard_for(conf)
    old = grafana_request(conf, "GET", f"/api/dashboards/uid/{d['uid']}")
    body = {"dashboard": d, "overwrite": True, "message": "noise-metrics.py --push-dashboard"}
    if (old.get("meta") or {}).get("folderUid"):
        body["folderUid"] = old["meta"]["folderUid"]
    res = grafana_request(conf, "POST", "/api/dashboards/db", body)
    if "error" in res:
        sys.exit(f"Grafana: pushing the dashboard: {res['error']}")
    print(f"dashboard {d['uid']}: version {res.get('version')} {res.get('status')}", file=sys.stderr)
    bad = 0
    for p in d["panels"]:
        for t in p.get("targets", []):
            q = {"queries": [{"refId": t["refId"], "datasource": t["datasource"], "query": t["query"].replace(
                "${bucket}", bucket), "intervalMs": 3600000, "maxDataPoints": 500}],
                 "from": "now-" + d.get("time", {}).get("from", "now-30d").removeprefix("now-"), "to": "now"}
            res = grafana_request(conf, "POST", "/api/ds/query", q)
            r = (res.get("results") or {}).get(t["refId"], {})
            err = res.get("error") or r.get("error")
            bad += bool(err) or not r.get("frames")
            print(f"  [{p['id']:2}] {p['title'][:60]:60} {err or frame_summary(r.get('frames'))}")
    return bad


def verify(influx, days=400):
    flux = (f'from(bucket: "{influx.bucket}") |> range(start: -{days}d) '
            f'|> group(columns: ["_measurement", "_field"]) |> count()')
    counts = {(r["_measurement"], r["_field"]): int(r["_value"]) for r in influx.query(flux)}
    print("InfluxDB points per measurement/field:")
    for (m, f), n in sorted(counts.items()):
        print(f"  {m:22} {f:24} {n:6}")
    flux = (f'from(bucket: "{influx.bucket}") |> range(start: -{days}d) '
            f'|> filter(fn: (r) => r._measurement == "ingest_daily" and r.dim == "total") |> sort(columns: ["_time"])')
    print("ingest_daily total per day:")
    for r in influx.query(flux):
        print(f"  {r['_time'][:10]}  {int(r['_value']):>10,}")
    flux = (f'from(bucket: "{influx.bucket}") |> range(start: -{days}d) '
            f'|> filter(fn: (r) => r._measurement == "elastic_billing" and (r._field == "ingest_gb" or '
            f'r._field == "total_ecu")) |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value") '
            f'|> group() |> sort(columns: ["_time"]) |> tail(n: 7)')
    print("elastic_billing, last 7 days:")
    for r in influx.query(flux):
        print(f"  {r['_time'][:10]}  {float(r['ingest_gb']):6.2f} GB  {float(r['total_ecu']):6.2f} ECU")
    flux = (f'from(bucket: "{influx.bucket}") |> range(start: -7d) '
            f'|> filter(fn: (r) => r._measurement == "noise_savings_total") |> last() '
            f'|> pivot(rowKey: ["source"], columnKey: ["_field"], valueColumn: "_value")')
    print("noise_savings_total, latest:")
    for r in influx.query(flux):
        print(f"  {r['source']:17} {int(r['filters']):3} filters, {float(r['saved_per_day']):>12,.0f} events/day, "
              f"{float(r['saved_gb_day']):.3f} GB/day, ${float(r['saved_usd_month']):.2f}/month; working "
              f"{r['working']}, partial {r['partial']}, leaking {r['leaking']}, not matching {r['not_matching']}, "
              f"untranslatable {r['untranslatable']}")
    return counts


def money(conf, search, influx, a, today, since):
    """Billing points, and cost(avg bytes) -> (GB per event, $ per GB) for the filter savings."""
    ecu_usd = float(conf.get("ECU_USD") or 1)
    lines, bill, why = [], None, ""
    stored = stored_billing(influx) if influx is not None else None
    if a.billing_days is None:
        a.billing_days = 3 if stored else BILLING_MAX_DAYS
    try:
        lines, bill = billing(Cloud(conf), conf, a.billing_days, today, ecu_usd)
    except ValueError as e:
        why = str(e)[:200]
    if bill is None:
        bill = stored
    day_events = total_per_day(search, max(since, today - 3 * DAY), today) if bill else {}
    factor, billed, sampled = calibration(search, bill, day_events)
    usd_per_gb = bill["ingest_rate"] * ecu_usd if bill and bill.get("ingest_rate") else None

    def cost(avg_bytes):
        return (None if avg_bytes is None else avg_bytes * factor / 1e9), usd_per_gb
    extra = {"ingest_rate": bill.get("ingest_rate") if bill else None, "ecu_usd": ecu_usd,
             "calibration": float(factor), "billed_bytes_per_event": billed,
             "source_bytes_per_event": sampled}
    return lines, bill, cost, extra, why


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
                                allow_abbrev=False)
    p.add_argument("--days", type=int, default=2, help="complete days to (re)write (default 2; 30 to backfill)")
    p.add_argument("--billing-days", type=int, default=None,
                   help=f"complete billed days to (re)write (default 3, or {BILLING_MAX_DAYS} while InfluxDB holds "
                        f"no billing yet; at most {BILLING_MAX_DAYS})")
    p.add_argument("--runs", default=RUNS, help="the agent's run-* folders (default agent/runs, or $NOISE_OUT)")
    p.add_argument("--env-file", default=METRICS_ENV, help="settings (default config/metrics.env)")
    p.add_argument("--key-file", default=READ_KEY, help="read-only key that may also list event filters "
                                                       "(default config/read.env)")
    p.add_argument("--print", action="store_true", help="print the line protocol, write nothing")
    p.add_argument("--verify", action="store_true", help="only read back what InfluxDB holds")
    p.add_argument("--push-dashboard", action="store_true", help="push the Grafana dashboard, query every panel")
    a = p.parse_args()
    a.env_file = os.path.expanduser(a.env_file)
    if not os.path.exists(a.env_file):
        sys.exit(f"No {a.env_file}.")
    if not 1 <= a.days <= 400 or not 0 <= (a.billing_days or 0) <= BILLING_MAX_DAYS:
        sys.exit(f"--days must be 1 to 400, --billing-days 0 to {BILLING_MAX_DAYS}")
    conf = nr.read_env_file(a.env_file)
    nr.load_safety()  # shells and interpreters, for stream_query
    if a.push_dashboard:
        sys.exit(1 if push_dashboard(conf, conf.get("INFLUXDB_BUCKET", "noise-cut")) else 0)
    influx = None if a.print else Influx(conf)
    if a.verify:
        verify(influx)
        return
    started = time.time()
    now = int(started)
    today = now - now % DAY
    search = Search(a.env_file, a.key_file)
    search.require_read_only()
    since = complete_from(search)
    lines, kept, skipped = daily(search, a.days, since)
    more, total = last_24h(search, now)
    lines += more
    store, why = store_stats(search, now)
    lines += store
    run_lines, run_baselines = runs(a.runs)
    lines += run_lines
    bill_lines, bill, cost, extra, bill_why = money(conf, search, influx, a, today, since)
    lines += bill_lines
    items = event_filters(search, conf)  # the same read-only key lists them
    start = since if since % DAY == 0 else since - since % DAY + DAY  # first complete day held in full
    stored = stored_baselines(influx) if influx else {}
    eff, base, results = filter_effects(search, items, start, today, now, stored, run_baselines, cost)
    lines += eff + base + totals(results, now, extra)
    by = lambda k: ", ".join(f"{n} {v}" for v, n in sorted(  # noqa: E731
        {r[k]: sum(x[k] == r[k] for x in results) for r in results}.items(), key=lambda x: -x[1]))
    msg = (f"; {len(items)} event filters ({by('source')}; {by('status')}): "
           f"{sum(r['saved'] for r in results):,.0f} events/day, {sum(r['gb_day'] for r in results):.3f} GB/day, "
           f"${sum(r['usd_month'] for r in results):.2f}/month saved; {len(base)} new baselines")
    print(f"metrics: {kept} complete days written" + (f", {skipped} older days skipped (partly expired in "
          f"Elasticsearch; stored in full from {datetime.datetime.fromtimestamp(since, datetime.timezone.utc):%Y-%m-%d %H:%M}Z)"
          if skipped else "") + f"; {total:,} events over 24h; {len(run_lines)} runs" + msg +
          f"; billing: {len(bill_lines)} days" + (f" (latest {bill.get('ingest_gb', 0):.2f} GB ingested at "
                                                   f"{bill.get('ingest_rate', 0)} ECU/GB, {bill.get('total_ecu', 0):.2f} ECU)"
                                                   if bill else "") + (f" ({bill_why})" if bill_why else "") +
          f"; storage stats: {'%d indices' % len(store) if store else 'unavailable (' + why + ')'}", file=sys.stderr)
    if a.print:
        print("\n".join(lines))
        return
    influx.write(lines)
    print(f"metrics: wrote {len(lines)} points to InfluxDB bucket {influx.bucket} in {time.time() - started:.1f}s",
          file=sys.stderr)


if __name__ == "__main__":
    main()
