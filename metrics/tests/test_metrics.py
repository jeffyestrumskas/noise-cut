"""Offline tests of noise-metrics.py: no network, no keys. python3 -m unittest discover agent/tests"""
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

METRICS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.dirname(METRICS)
sys.path[:0] = [METRICS, ROOT, os.path.join(ROOT, "agent")]
spec = importlib.util.spec_from_file_location("noise_metrics", os.path.join(METRICS, "noise-metrics.py"))
nm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nm)
nm.nr.load_safety()

FILTER = {"id": 3, "os": "linux", "note": "timer job",
          "conditions": [{"field": "process.executable", "value": "/usr/lib/foo/foo-sync"},
                         {"field": "event.category", "value": "process"}],
          "gate": {"ok": True, "events": 4800, "hosts": ["nas.example.lan"]}}
CONF = {"INFLUXDB_URL": "https://influxdb.example.lan", "INFLUXDB_ORG_ID": "0123abcd", "INFLUXDB_API_KEY": "t0ken"}


class FakeSearch:
    def __init__(self, n=7, buckets=None, firsts=None):
        self.n, self.bodies, self.buckets, self.firsts = n, [], buckets or [], firsts or []

    def search(self, body, index="logs-*"):
        self.bodies.append(body)
        aggs = body.get("aggs", {})
        if "d" in aggs:
            return {"aggregations": {"d": {"buckets": self.buckets}}}
        if "first" in aggs.get("ds", {}).get("aggs", {}):
            return {"aggregations": {"ds": {"buckets": [{"key": k, "doc_count": c, "first": {"value": t}}
                                                        for k, c, t in self.firsts]}}}
        return {"hits": {"total": {"value": self.n}}, "aggregations": {"ds": {"buckets": []}}}


def write_run(root, name, applied, proposals, rows=None):
    d = os.path.join(root, name, "data")
    os.makedirs(d)
    for f, v in (("applied.json", applied), ("proposals.json", proposals), ("rows.json", rows)):
        if v is not None:
            with open(os.path.join(d, f), "w") as fh:
                json.dump(v, fh)


class LineProtocol(unittest.TestCase):
    def test_types_and_escaping(self):
        s = nm.line("m", {"key": "a b,c=d", "empty": ""}, {"i": 3, "f": 1.5, "b": True, "s": 'x "y"\nz', "n": None}, 10)
        self.assertEqual(s, 'm,key=a\\ b\\,c\\=d i=3i,f=1.5,b=true,s="x \\"y\\" z" 10')

    def test_one_line_per_point(self):
        self.assertNotIn("\n", nm.line("m", {"k": "a\nb"}, {"s": "a\r\nb"}, 1))


class Elastic(unittest.TestCase):
    def test_days_before_retention_are_skipped(self):
        # The big dataset is stored from day 2 12:00 on: day 2 is partial, days 3-4 are complete.
        day = 86400
        firsts = [("endpoint.events.process", 900, (2 * day + 43200) * 1000), ("system.syslog", 100, 0)]
        self.assertEqual(nm.complete_from(FakeSearch(firsts=firsts)), 2 * day + 43200)
        empty = {d: {"buckets": [], "sum_other_doc_count": 0} for d in nm.DIMS}
        buckets = [dict(empty, key=k * day * 1000, doc_count=k) for k in (2, 3, 4)]
        buckets[2]["host"] = {"buckets": [{"key": "nas.example.lan", "doc_count": 3}], "sum_other_doc_count": 1}
        lines, kept, skipped = nm.daily(FakeSearch(buckets=buckets), 30, 2 * day + 43200)
        self.assertEqual((kept, skipped), (2, 1))
        self.assertIn(f"ingest_daily,dim=host,key=nas.example.lan events=3i {4 * day}", lines)
        self.assertIn(f"ingest_daily,dim=host,key=(other) events=1i {4 * day}", lines)

    def test_small_datasets_dont_cut_history(self):
        firsts = [("endpoint.events.process", 990, 5000), ("new.tiny", 10, 9_000_000)]
        self.assertEqual(nm.complete_from(FakeSearch(firsts=firsts)), 5)


class Runs(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        self.fp = nm.ng.fingerprint(FILTER)
        made = {"id": 3, "ok": True, "events": 4800, "hosts": ["nas.example.lan"], "fingerprint": self.fp,
                "filter": "linux: process.executable=/usr/lib/foo/foo-sync"}
        props = {"total": 100000, "since": "24h", "filters": [FILTER], "seconds": 12.5, "tokens_in": 10}
        write_run(self.root, "run-20261101T120000Z", {"created": "2026-11-01T12:30:00+00:00", "dry_run": True,
                                                       "filters": [dict(made, events=4700)], "rejected": [{}]}, props,
                  {"total": 100000, "proposals": [{"count": 6000}], "skipped": []})
        write_run(self.root, "run-20261102T120000Z", {"created": "2026-11-02T12:30:00+00:00", "dry_run": False,
                                                       "filters": [made, dict(made, ok=False, id=4)]}, dict(props, since="6h"))
        write_run(self.root, "run-20261103T120000Z", None, None)  # failed before apply

    def tearDown(self):
        self.tmp.cleanup()

    def test_run_points(self):
        lines, created = nm.runs(self.root)
        self.assertEqual(len(lines), 3)
        self.assertTrue(lines[0].startswith("noise_run,mode=dry_run "))
        self.assertIn("save_events=4700i", lines[0])
        self.assertIn("propose_seconds=12i", lines[0])  # always an int, as InfluxDB wants one type per field
        self.assertIn("rows_events=6000i", lines[0])
        self.assertTrue(lines[1].startswith("noise_run,mode=apply ") and "created=1i" in lines[1])
        self.assertTrue(lines[2].startswith("noise_run,mode=incomplete "))
        self.assertEqual(created, {self.fp: 4800 * 4})  # only the apply run's ok filter, per day from 6h

    def test_kibana_item_has_the_run_fingerprint(self):
        item = {"os_types": ["linux"], "tags": ["policy:all"],
                "entries": [dict(e, operator="included") for e in nm.ng.to_entries(FILTER)]}
        self.assertEqual(nm.item_fingerprint(item), self.fp)


def item(fid="f1", entries=None, os_types=("linux",), tags=("policy:all",), created="2026-10-01T10:00:00.000Z",
         description=""):
    return {"id": fid, "item_id": fid, "name": f"filter {fid}", "description": description, "created_at": created,
            "updated_at": created, "os_types": list(os_types), "tags": list(tags),
            "entries": entries or [{"field": "process.executable", "operator": "included", "type": "match",
                                    "value": "/usr/lib/foo/foo-sync"},
                                   {"field": "event.category", "operator": "included", "type": "match",
                                    "value": "process"}]}


class Filters(unittest.TestCase):
    def test_source_markers(self):
        self.assertEqual(nm.source(item(description="Added by noise-cut.py 2026-10-05. noise-agent: timer")),
                         "noise-agent")
        self.assertEqual(nm.source(item(description="Added by noise-cut.py 2026-10-05. 948 events over the "
                                                    "last 6h from nas.example.lan.")), "noise-cut.py")
        self.assertEqual(nm.source(dict(item(), item_id="noise-cut-0123abcd")), "noise-cut.py")
        self.assertEqual(nm.source(item(description="alice: backup job")), "manual")
        # filters made before the rename keep their old markers
        self.assertEqual(nm.source(item(description="Added by elastic-noise.py 2026-10-05. 948 events over the "
                                                    "last 24h on nas.example.lan")), "noise-cut.py")
        self.assertEqual(nm.source(dict(item(), item_id="elastic-noise-0123abcd")), "noise-cut.py")

    def test_description_baseline(self):
        it = item(description="Added by noise-cut.py 2026-10-05. 1,200 events over the last 6h from "
                              "nas.example.lan.")
        self.assertEqual(nm.description_baseline(it), 4800)
        self.assertIsNone(nm.description_baseline(item(description="Added by noise-cut.py 2026-10-07. cron")))

    def test_query_match_any_wildcard_excluded(self):
        q, how = nm.filter_query(item(entries=[
            {"field": "host.name", "operator": "included", "type": "match_any", "value": ["nas.example.lan", "nas"]},
            {"field": "process.executable", "operator": "included", "type": "wildcard", "value": "/opt/app/*/bin/app"},
            {"field": "process.name", "operator": "excluded", "type": "match", "value": "sh"},
            {"field": "file.path.caseless", "operator": "included", "type": "match", "value": "/srv/A.log"}]))
        self.assertEqual(how, "exact")
        self.assertIn({"terms": {"host.os.type": ["linux"]}}, q["bool"]["filter"])
        self.assertIn({"terms": {"host.name": ["nas.example.lan", "nas"]}}, q["bool"]["filter"])
        self.assertIn({"wildcard": {"process.executable": {"value": "/opt/app/*/bin/app"}}}, q["bool"]["filter"])
        self.assertIn({"term": {"file.path": {"value": "/srv/A.log", "case_insensitive": True}}}, q["bool"]["filter"])
        self.assertEqual(q["bool"]["must_not"], [{"term": {"process.name": {"value": "sh"}}}])

    def test_descendants_match_the_parent(self):
        q, how = nm.filter_query(item(tags=["filter_process_descendants"], entries=[
            {"field": "process.command_line", "operator": "included", "type": "match", "value": "/bin/sh /opt/job.sh"}]))
        self.assertEqual(how, "approx")
        self.assertIn({"term": {"process.parent.command_line": {"value": "/bin/sh /opt/job.sh"}}}, q["bool"]["filter"])

    def test_nested_and_untranslatable(self):
        q, how = nm.filter_query(item(os_types=["windows"], entries=[
            {"field": "process.Ext.code_signature", "type": "nested", "entries": [
                {"field": "subject_name", "operator": "included", "type": "match", "value": "Example Corp"},
                {"field": "trusted", "operator": "included", "type": "match", "value": "true"}]}]))
        self.assertEqual(how, "approx")
        nested = q["bool"]["filter"][1]["bool"]["filter"]
        self.assertIn({"term": {"process.Ext.code_signature.subject_name": {"value": "Example Corp",
                                                                            "case_insensitive": True}}}, nested)
        for bad in ([{"field": "file.path", "operator": "included", "type": "list", "list": {"id": "x"}}], []):
            with self.assertRaises(nm.Untranslatable):
                nm.filter_query(item(entries=bad) if bad else dict(item(), entries=[]))
        with self.assertRaises(nm.Untranslatable):  # descendants can only move process.* to the parent
            nm.filter_query(item(tags=["filter_process_descendants"], entries=[
                {"field": "event.category", "operator": "included", "type": "match", "value": "file"}]))


D = 86400
NOW = 1793900000
TODAY = NOW - NOW % D


class Effect(unittest.TestCase):
    days = {TODAY - k * D: 0 for k in range(7, 0, -1)}

    def test_created_inside_the_window(self):
        days = dict(self.days)
        created = TODAY - 4 * D + 3600
        for d in days:
            days[d] = 1000 if d < created - 3600 else 400 if d == created - 3600 else 10
        r = nm.effect(days, created)
        self.assertEqual((r["baseline"], r["baseline_source"], r["baseline_days"]), (1000, "window", 3))
        self.assertEqual(r["current"], 10)  # the creation day is skipped
        self.assertEqual((r["saved"], r["status"]), (990, "working"))

    def test_created_before_the_window(self):
        days = {d: 300 for d in self.days}
        old = TODAY - 30 * D
        self.assertEqual(nm.effect(days, old)["status"], "leaking")  # no baseline, still matching
        r = nm.effect(days, old, None, (1000.0, "description"))
        self.assertEqual((r["baseline_source"], r["saved"], r["status"]), ("description", 700, "partial"))
        r = nm.effect(days, old, (320.0, "window"), (1000.0, "description"))
        self.assertEqual((r["baseline_source"], r["status"]), ("window", "leaking"))  # stored wins
        r = nm.effect({d: 0 for d in days}, old)
        self.assertEqual((r["baseline"], r["saved"], r["status"]), (None, 0, "not matching"))

    def test_too_new_and_stray_events(self):
        self.assertEqual(nm.effect({TODAY - D: 50}, TODAY - D + 60)["status"], "too new")
        self.assertEqual(nm.status(None, 0.3), "not matching")
        self.assertEqual(nm.status(0, 2.0), "leaking")


class EffectSearch:
    """Elasticsearch stand-in for filter_effects: per-filter daily counts, docs of a fixed size."""
    def __init__(self, per_day):
        self.per_day, self.bodies = per_day, []

    def search(self, body, index="logs-*"):
        self.bodies.append(body)
        if "aggs" in body:
            buckets = {k: {"d": {"buckets": [{"key": (TODAY - j * D) * 1000, "doc_count": self.per_day.get(k, 0)}
                                             for j in range(7, 0, -1)]}} for k in body["aggs"]["f"]["filters"]["filters"]}
            return {"aggregations": {"f": {"buckets": buckets}}}
        return {"hits": {"hits": [{"_source": {"x": "y" * 992}}] * 3}}  # 1,000 bytes each


class StreamSearch(EffectSearch):
    """EffectSearch whose second count (the streams, after the filters) has its own per-day numbers."""
    def __init__(self, per_day, stream_per_day):
        super().__init__(per_day)
        self.counts = [per_day, stream_per_day]

    def search(self, body, index="logs-*"):
        if "aggs" in body:
            self.per_day = self.counts.pop(0) if self.counts else self.per_day
        return super().search(body, index)


class Savings(unittest.TestCase):
    def test_effects_totals_and_dollars(self):
        items = [item("a", description="Added by noise-cut.py 2026-10-01. 24,000 events over the last 24h from "
                                       "nas.example.lan."),
                 item("b"), item("c", entries=[{"field": "file.path", "type": "list", "list": {"id": "x"}}])]
        search = EffectSearch({"a": 0, "b": 0})
        cost = lambda b: (None if b is None else b * 1.0 / 1e9, 0.6)  # noqa: E731  $0.60 per GB
        lines, base, res = nm.filter_effects(search, items, TODAY - 7 * D, TODAY, NOW, {}, {}, cost)
        by = {r["id"]: r for r in res}
        self.assertEqual((by["a"]["status"], by["a"]["saved"]), ("working", 24000))
        self.assertAlmostEqual(by["a"]["gb_day"], 0.024)            # 24,000 x 1,000 bytes
        self.assertAlmostEqual(by["a"]["usd_month"], 0.024 * 30 * 0.6)
        self.assertEqual(by["b"]["status"], "not matching")
        self.assertEqual(by["c"]["status"], "untranslatable")
        self.assertEqual(len(base), 1)
        self.assertIn("noise_filter_baseline,filter_id=a baseline_per_day=24000.0", base[0])
        self.assertTrue(any(l.startswith("noise_filter_effect,filter_id=a,name=filter\\ a,os=linux,source=noise-cut.py,"
                                         "status=working ") for l in lines))
        # stored baselines are not written again
        _, base, _ = nm.filter_effects(search, items, TODAY - 7 * D, TODAY, NOW, {"a": (24000.0, "description")}, {}, cost)
        self.assertEqual(base, [])
        tot = nm.totals(res, NOW, {"ingest_rate": 0.6})
        self.assertTrue(tot[0].startswith("noise_savings_total,source=all filters=3i,saved_per_day=24000.0,"))
        self.assertIn("working=1i,partial=0i,leaking=0i,drifted=0i,not_matching=1i,untranslatable=1i", tot[0])

    def test_stream_query(self):
        cmd = lambda v: [{"field": "process.command_line", "operator": "included", "type": "match", "value": v},  # noqa: E731
                         {"field": "event.category", "operator": "included", "type": "match", "value": "process"}]
        q = nm.stream_query(item(entries=cmd("/bin/bash /opt/slides/slideshow.sh --fast")))
        self.assertIn({"wildcard": {"process.command_line": {"value": "*/opt/slides/slideshow.sh*"}}}, q["bool"]["filter"])
        self.assertIn({"term": {"event.category": "process"}}, q["bool"]["filter"])
        q = nm.stream_query(item(entries=cmd("/usr/sbin/upsd -u nut")))
        self.assertIn({"term": {"process.executable": {"value": "/usr/sbin/upsd"}}}, q["bool"]["filter"])
        q = nm.stream_query(item(entries=cmd("/usr/sbin/upsd -u nut")[:1], tags=("filter_process_descendants",)))
        self.assertEqual(q["bool"]["filter"][0], {"term": {"process.parent.executable": {"value": "/usr/sbin/upsd"}}})
        self.assertIsNone(nm.stream_query(item()))                                   # no command line
        self.assertIsNone(nm.stream_query(item(entries=cmd("bash tools/watch.sh"))))  # no full path

    def test_drifted_filter_saves_nothing(self):
        cmd = [{"field": "process.command_line", "operator": "included", "type": "match",
                "value": "/bin/bash /opt/slides/slideshow.sh --fast"},
               {"field": "event.category", "operator": "included", "type": "match", "value": "process"}]
        desc = "Added by noise-cut.py 2026-10-01. 24,000 events over the last 24h from nas.example.lan."
        items = [item("s", entries=cmd, description=desc), item("w", entries=cmd, description=desc)]
        search = StreamSearch({"s": 0, "w": 0}, {"s": 23000, "w": 100})
        cost = lambda b: (None if b is None else b * 1.0 / 1e9, 0.6)  # noqa: E731
        _, _, res = nm.filter_effects(search, items, TODAY - 7 * D, TODAY, NOW, {}, {}, cost)
        by = {r["id"]: r for r in res}
        self.assertEqual((by["s"]["status"], by["s"]["saved"], by["s"]["usd_month"]), ("drifted", 0.0, 0.0))
        self.assertEqual((by["w"]["status"], by["w"]["saved"]), ("working", 24000))
        # made inside the window: the stream fell by about what the filter hid, so it works
        r = {"status": "working", "baseline": 1000}
        self.assertFalse(nm.drifted(r, {"current": 2100, "baseline": 3000, "baseline_source": "window"}))
        self.assertTrue(nm.drifted(r, {"current": 2900, "baseline": 3000, "baseline_source": "window"}))
        self.assertFalse(nm.drifted(dict(r, status="leaking"), {"current": 2900, "baseline": 3000,
                                                                "baseline_source": "window"}))


class Billing(unittest.TestCase):
    RES = {"total_ecu": 1.2, "products": [{"product_line_items": [
        {"name": "Security Analytics Complete - Data ingestion (Example region)", "total_ecu": 1.18,
         "quantity": {"value": 1.9667}, "rate": {"value": 0.6}},
        {"name": "Security Analytics Complete - Data retention (Example region)", "total_ecu": 0.02,
         "quantity": {"value": 0.5}, "rate": {"value": 0.04}}]}]}

    def test_fields(self):
        f = nm.billing_fields(self.RES, 0.9)
        self.assertEqual((f["ingest_gb"], f["ingest_ecu"], f["ingest_rate"], f["retention_gb"]), (1.9667, 1.18, 0.6, 0.5))
        self.assertAlmostEqual(f["total_usd"], 1.08)

    def test_day_by_day_get_only(self):
        calls = []

        class Cloud:
            def get(self, path):
                calls.append(path)
                if path == "/api/v1/organizations":
                    return {"organizations": [{"id": "1234"}]}
                if path.startswith("/api/v1/serverless/projects/security"):
                    return {"items": [{"id": "abcd", "metadata": {"created_at": "2026-01-01T00:00:00Z"}}]}
                return Billing.RES
        lines, latest = nm.billing(Cloud(), {}, 3, TODAY, 1.0)
        self.assertEqual(len(lines), 3)
        self.assertTrue(all(l.startswith("elastic_billing total_ecu=1.2,") for l in lines))
        self.assertEqual(latest["ts"], TODAY - D)
        self.assertIn("/api/v2/billing/organizations/1234/costs/instances/abcd/items?from=", calls[2])
        lines, _ = nm.billing(Cloud(), {}, 500, TODAY, 1.0)
        self.assertEqual(len(lines), nm.BILLING_MAX_DAYS)  # capped

    def test_cloud_needs_a_key(self):
        with self.assertRaises(ValueError):
            nm.Cloud({})


class Dashboard(unittest.TestCase):
    def test_import_input_and_push_copy(self):
        with open(nm.DASHBOARD) as fh:
            raw = fh.read()
        d = json.loads(raw)
        self.assertEqual(d["__inputs"][0]["name"], "DS_INFLUXDB")
        for p in d["panels"]:
            for t in p.get("targets", []):
                self.assertEqual(t["datasource"]["uid"], "${DS_INFLUXDB}")
        pushed = nm.dashboard_for({"GRAFANA_DATASOURCE_UID": "ds123", "GRAFANA_DASHBOARD_UID": "dash1"})
        self.assertEqual(pushed["uid"], "dash1")
        self.assertNotIn("__inputs", pushed)
        self.assertNotIn("${DS_INFLUXDB}", json.dumps(pushed))
        var = next(v for v in pushed["templating"]["list"] if v["name"] == "bucket")
        self.assertEqual(var["current"]["value"], "noise-cut")
        pushed = nm.dashboard_for({"GRAFANA_DATASOURCE_UID": "ds123", "INFLUXDB_BUCKET": "old-bucket"})
        var = next(v for v in pushed["templating"]["list"] if v["name"] == "bucket")
        self.assertEqual((var["query"], var["current"]["value"]), ("old-bucket", "old-bucket"))
        self.assertIn("noise_filter_effect", raw)
        self.assertIn("elastic_billing", raw)


class Conn:
    sent = []

    def __init__(self, host, port, context=None, timeout=None):
        self.sock = mock.Mock()
        self.sock.getpeercert.return_value = b"leaf"

    def connect(self):
        pass

    def request(self, *a, **k):
        Conn.sent.append((a, k))

    def getresponse(self):
        return mock.Mock(status=204, read=lambda: b"")

    def close(self):
        pass


class Influx(unittest.TestCase):
    def setUp(self):
        Conn.sent = []

    def test_needs_https_and_settings(self):
        for bad in ({"INFLUXDB_URL": "http://influxdb.example.lan"}, {"INFLUXDB_ORG_ID": ""}):
            with self.assertRaises(SystemExit):
                nm.Influx(dict(CONF, **bad))

    def test_missing_ca_file_is_an_error_not_a_fallback(self):
        with self.assertRaises(SystemExit):
            nm.Influx(dict(CONF, INFLUXDB_CA_FILE="nope.crt", INFLUXDB_CERT_SHA256="ab" * 32))

    def test_wrong_pin_sends_nothing(self):
        i = nm.Influx(dict(CONF, INFLUXDB_CERT_SHA256="ab" * 32))
        with mock.patch.object(nm.http.client, "HTTPSConnection", Conn), self.assertRaises(SystemExit):
            i.write(["m f=1i 1"])
        self.assertEqual(Conn.sent, [])

    def test_right_pin_writes(self):
        pin = ":".join(hashlib.sha256(b"leaf").hexdigest()[i:i + 2].upper() for i in range(0, 64, 2))
        i = nm.Influx(dict(CONF, INFLUXDB_CERT_SHA256=pin))
        with mock.patch.object(nm.http.client, "HTTPSConnection", Conn):
            i.write(["m f=1i 1", "m f=2i 2"])
        (method, path), k = Conn.sent[0]
        self.assertEqual(method, "POST")
        self.assertIn("orgID=0123abcd", path)
        self.assertIn("bucket=noise-cut", path)
        self.assertEqual(k["body"], b"m f=1i 1\nm f=2i 2")
        self.assertEqual(k["headers"]["Authorization"], "Token t0ken")

    def test_query_parses_csv_tables(self):
        csv_body = (b",result,table,_measurement,_field,_value\r\n,_result,0,noise_run,created,1\r\n\r\n"
                    b",result,table,_measurement,_field,_value\r\n,_result,1,ingest_daily,events,7\r\n")
        i = nm.Influx(dict(CONF, INFLUXDB_CERT_SHA256=hashlib.sha256(b"leaf").hexdigest()))
        with mock.patch.object(nm.Influx, "_request", return_value=csv_body):
            rows = i.query("x")
        self.assertEqual([(r["_measurement"], r["_value"]) for r in rows], [("noise_run", "1"), ("ingest_daily", "7")])


if __name__ == "__main__":
    unittest.main()
