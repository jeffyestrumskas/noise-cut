#!/usr/bin/env python3
r"""Explain a stream of Elastic Defend events: who makes it, how steadily, and what else on the
same host moves in step with it.

  explain.py --host desk01 --match process.executable=/usr/bin/gnome-shell --match event.action=memfd_create
  explain.py --host web01 --match 'process.command_line=/bin/bash /opt/x.sh' --since 6h

Uses the same settings files as noise-cut.py, and only ever searches (es_read.py).
"""
import argparse
import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from es_read import Search  # noqa: E402
from noise_rules import term_or_wildcard, window_seconds  # noqa: E402

INDEX = "logs-*"
# Process detail that repeats the same info at every level; left out of the event dump.
LEADERS = ("process.entry_leader", "process.group_leader", "process.session_leader", "process.previous",
           "process.real_", "process.group.", "process.user.", "process.parent.real_", "process.parent.group",
           "process.parent.user", "process.parent.supplemental", "process.supplemental", "process.parent.args")
SKIP_SUFFIXES = ("hash.sha256", "hash.sha1", "hash.md5", "args_count", "interactive")


def search(api, query, aggs=None, size=0, sort=None, index=INDEX):
    body = {"size": size, "track_total_hits": True, "query": query}
    if aggs:
        body["aggs"] = aggs
    if sort:
        body["sort"] = sort
    return api.search(body, index)


def flat(x, prefix=""):
    if isinstance(x, dict):
        for k, v in x.items():
            yield from flat(v, f"{prefix}{k}.")
    else:
        yield prefix[:-1], x


def pearson(a, b):
    n = len(a)
    if n < 3:
        return 0.0
    ma, mb = sum(a) / n, sum(b) / n
    va = sum((x - ma) ** 2 for x in a)
    vb = sum((y - mb) ** 2 for y in b)
    if not va or not vb:
        return 0.0
    return sum((x - ma) * (y - mb) for x, y in zip(a, b)) / math.sqrt(va * vb)


def series(buckets, keys):
    got = {b["key"]: b["doc_count"] for b in buckets}
    return [got.get(k, 0) for k in keys]


def terms(field, size=10, **sub):
    agg = {"terms": {"field": field, "size": size}}
    if sub:
        agg["aggs"] = sub
    return agg


def show_terms(title, buckets, total=None, width=110):
    if not buckets:
        return
    print(f"\n-- {title}")
    for b in buckets:
        share = f"{b['doc_count'] / total:6.1%}  " if total else ""
        print(f"  {b['doc_count']:>9,}  {share}{str(b.get('key_as_string', b['key']))[:width]}")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
                                allow_abbrev=False)
    p.add_argument("--host", required=True, help="host.name the events come from")
    p.add_argument("--match", action="append", default=[], metavar="FIELD=VALUE",
                   help="condition picking the events to explain; * and ? in VALUE are wildcards (repeatable)")
    p.add_argument("--since", default="1h", help="window to analyse (default 1h)")
    p.add_argument("--interval", default="1m", help="bucket size for the timing analysis (default 1m)")
    p.add_argument("--top", type=int, default=12, help="rows per section (default 12)")
    p.add_argument("--env-file", help="settings file, as in noise-cut.py")
    p.add_argument("--no-sample", action="store_true",
                   help="leave out the sample event (its args, IDs, IPs, user); counts and timing only")
    a = p.parse_args()
    if not a.match:
        sys.exit("Give at least one --match FIELD=VALUE.")
    api = Search(a.env_file)
    print(f"(using the API key from {api.env_file})", file=sys.stderr)
    run(api, a.host, [m.split("=", 1) for m in a.match], a.since, a.interval, a.top, sample=not a.no_sample)


def run(api, host, match, since, interval, top=12, sample=False):
    """The report, printed. match: [(field, value), ...]. sample=False leaves out the latest event."""
    a_match = [f"{f}={v}" for f, v in match]
    window = [{"range": {"@timestamp": {"gte": f"now-{since}"}}}, {"term": {"host.name": host}}]
    target = [term_or_wildcard(f, v) for f, v in match]
    hist = {"date_histogram": {"field": "@timestamp", "fixed_interval": interval,
                               "extended_bounds": {"min": f"now-{since}", "max": "now"}}}

    # 1. The stream itself: how many, how steady, which process(es).
    res = search(api, {"bool": {"filter": window + target}}, size=1, sort=[{"@timestamp": "desc"}], aggs={
        "t": hist, "pids": terms("process.entity_id", 5), "names": terms("process.name", 5)})
    n = res["hits"]["total"]["value"]
    print(f"{n:,} events on {host} over the last {since} match {' '.join(a_match)}")
    if not n:
        return
    tb = res["aggregations"]["t"]["buckets"]
    keys = [b["key"] for b in tb]
    ts = series(tb, keys)
    mean = sum(ts) / len(ts)
    sd = math.sqrt(sum((x - mean) ** 2 for x in ts) / len(ts))
    per_sec = mean / window_seconds(interval) if window_seconds(interval) else 0
    print(f"rate: {mean:.1f} per {interval} (~{per_sec:.2f}/s), variation {sd / mean if mean else 0:.0%} "
          f"({'steady, timer-like' if mean and sd / mean < 0.2 else 'bursty'})")
    print("per " + interval + ": " + " ".join(str(x) for x in ts[-30:]))

    doc = res["hits"]["hits"][0]["_source"]
    if sample:
        print("\n-- latest event (process, user and Ext detail)")
    for k, v in (flat(doc) if sample else []):
        if k.startswith(("process.", "user.name", "file.", "event.action", "dll.", "dns.", "destination.",
                         "source.")) and not k.startswith(LEADERS) and not k.endswith(SKIP_SUFFIXES):
            print(f"  {k} = {str(v)[:150]}")
    entity = doc.get("process", {}).get("entity_id")
    user = doc.get("user", {}).get("name")
    if len(res["aggregations"]["pids"]["buckets"]) > 1:
        show_terms("more than one process makes these events", res["aggregations"]["pids"]["buckets"], n)

    # 2. Everything else that process did in the window.
    if entity:
        same = {"bool": {"filter": window + [{"term": {"process.entity_id": entity}}]}}
        r = search(api, same, aggs={"act": terms("event.action", top), "files": terms("file.path", top),
                                     "dst": terms("destination.ip", top)})
        print(f"\n== everything process {entity} did ({r['hits']['total']['value']:,} events)")
        show_terms("by event.action", r["aggregations"]["act"]["buckets"])
        show_terms("files touched", r["aggregations"]["files"]["buckets"])
        show_terms("network destinations", r["aggregations"]["dst"]["buckets"])

        # 3. What it started (children and deeper).
        kids = {"bool": {"filter": window, "should": [{"term": {"process.parent.entity_id": entity}},
                                                      {"term": {"process.Ext.ancestry": entity}}],
                         "minimum_should_match": 1}}
        r = search(api, kids, aggs={"cmd": terms("process.command_line", top)})
        if r["hits"]["total"]["value"]:
            show_terms(f"processes it started ({r['hits']['total']['value']:,} events)", r["aggregations"]["cmd"]["buckets"])
        else:
            print("\n-- it started no processes in this window")

    # 4. What else on the host moves in step with it, minute by minute.
    others = {"bool": {"filter": window, "must_not": target}}
    r = search(api, others, aggs={
        "proc": terms("process.name", 60, t=hist),
        "procact": {"multi_terms": {"terms": [{"field": "process.name"}, {"field": "event.action"}], "size": 80},
                    "aggs": {"t": hist}},
        "peer": terms("destination.ip", 30, t=hist),
    })
    rows = []
    for label, agg in (("process", "proc"), ("process+action", "procact"), ("network peer", "peer")):
        for b in r["aggregations"][agg]["buckets"]:
            s = series(b["t"]["buckets"], keys)
            c = pearson(ts, s)
            key = " / ".join(b["key"]) if isinstance(b["key"], list) else str(b["key"])
            rows.append((c, label, key, sum(s), sum(s) / len(s)))
    rows.sort(key=lambda x: -x[0])
    print(f"\n== other activity on {host} that rises and falls with it (correlation per {interval}; 1.0 = same shape)")
    print("   ratio = their events per target event; a steady ratio of ~1, 0.5, 2... hints at one causing the other")
    for c, label, key, total, avg in rows[: top]:
        print(f"  {c:5.2f}  {label:<15} {total:>8,} events  ratio {total / n:5.2f}  {key[:90]}")

    # 5. Who is connected to the host (remote desktop, screen sharing, VNC...).
    net = {"bool": {"filter": window}}
    r = search(api, net, aggs={
        "accepted": {"filter": {"term": {"event.action": "connection_accepted"}},
                     "aggs": {"x": {"multi_terms": {"terms": [{"field": "process.name"}, {"field": "destination.port"},
                                                              {"field": "source.ip"}], "size": top}}}},
        "out": {"multi_terms": {"terms": [{"field": "process.name"}, {"field": "destination.port"}], "size": top}},
    }, index="logs-endpoint.events.network-*")  # other datasets map the ports/IPs differently
    show_terms("inbound connections accepted (process / local port / from)", r["aggregations"]["accepted"]["x"]["buckets"])
    show_terms("outbound connections (process / port)", r["aggregations"]["out"]["buckets"])

    # 6. What the same user is running (exec events), for context.
    if user:
        r = search(api, {"bool": {"filter": window + [{"term": {"user.name": user}}, {"term": {"event.action": "exec"}}]}},
                   aggs={"x": terms("process.executable", top)})
        show_terms(f"programs {user} started in the window", r["aggregations"]["x"]["buckets"])


if __name__ == "__main__":
    main()
