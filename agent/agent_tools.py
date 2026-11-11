"""The only tools a model gets: three read-only queries. This file is the whole list.

  breakdown   counts per field for events matching some conditions
  count       how many events a proposed filter would match
  explain     how steady a stream is and what moves with it (explain.py, never a sample event)

Each tool takes typed arguments, checked here against its schema before anything runs (unknown
or malformed arguments are refused), and searches Elasticsearch through es_read.Search, which
can only search. There is no shell, no command line, no file access, no way to create, change
or delete anything. submit/verdict (in noise-agent.py) only hand data back.
"""
import contextlib
import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.dirname(HERE)]  # this folder, and the shared code one up
import explain as explain_report  # noqa: E402
import noise_gate as ng
import pseudo as ps  # noqa: E402
import noise_rules as nr  # noqa: E402

SINCE = ["1h", "6h", "24h", "3d", "7d"]
INTERVAL = ["1m", "5m", "15m", "1h"]
MAX_BUCKETS = 2000  # explain: since / interval
MAX_OUTPUT = 14000  # longer output keeps its head and tail
# Fields a model may query or group by: the filter fields plus context. Nothing else.
QUERY_FIELDS = ng.FILTER_FIELDS + ("host.name", "data_stream.dataset", "event.type", "event.outcome",
                                   "user.name", "process.working_directory", "destination.domain",
                                   "destination.address", "container.name", "systemd.unit")
HOST = r"[A-Za-z0-9][A-Za-z0-9._-]{0,252}"


def condition_list(fields, most):
    return {"type": "array", "minItems": 1, "maxItems": most, "items": {
        "type": "object", "additionalProperties": False, "required": ["field", "value"],
        "properties": {"field": {"type": "string", "enum": list(fields)},
                       "value": {"type": "string", "minLength": 1, "maxLength": ng.MAX_VALUE,
                                 "description": "exact value; * and ? make it a wildcard"}}}}


SCHEMAS = {
    "breakdown": {
        "description": "Count the events matching `where`, grouped by each `group_by` field (top values). "
                       "For what a process starts, put it in process.parent.* fields.",
        "parameters": {"type": "object", "additionalProperties": False, "required": ["where", "group_by"],
                       "properties": {
                           "where": condition_list(QUERY_FIELDS, 6),
                           "group_by": {"type": "array", "minItems": 1, "maxItems": 4,
                                        "items": {"type": "string", "enum": list(QUERY_FIELDS)}},
                           "host": {"type": "string", "pattern": HOST},
                           "since": {"type": "string", "enum": SINCE},
                           "top": {"type": "integer", "minimum": 1, "maximum": 30}}}},
    "count": {
        "description": "How many events a filter with exactly these conditions would hide (descendants=true: "
                       "what the matching process starts, direct children only). Check every filter with it.",
        "parameters": {"type": "object", "additionalProperties": False, "required": ["os", "conditions"],
                       "properties": {
                           "os": {"type": "string", "enum": list(ng.OS_TYPES)},
                           "conditions": condition_list(ng.FILTER_FIELDS, ng.MAX_CONDITIONS),
                           "descendants": {"type": "boolean"},
                           "since": {"type": "string", "enum": SINCE}}}},
    "explain": {
        "description": "For one host: how steady the matching stream is per interval, which processes make it, "
                       "what else they did and started, and what other activity rises and falls with it.",
        "parameters": {"type": "object", "additionalProperties": False, "required": ["host", "where"],
                       "properties": {
                           "host": {"type": "string", "pattern": HOST},
                           "where": condition_list(QUERY_FIELDS, 6),
                           "since": {"type": "string", "enum": SINCE},
                           "interval": {"type": "string", "enum": INTERVAL}}}},
}


def check(schema, value, path="arguments"):
    """Validate value against the small JSON Schema subset used here. Raises ValueError."""
    t = schema.get("type")
    if t == "object":
        if not isinstance(value, dict):
            raise ValueError(f"{path} must be an object")
        props = schema.get("properties", {})
        extra = set(value) - set(props)
        if extra and schema.get("additionalProperties") is False:
            raise ValueError(f"{path}: unknown argument(s) {', '.join(sorted(map(str, extra)))}; "
                             f"allowed: {', '.join(props)}")
        for k in schema.get("required", []):
            if k not in value:
                raise ValueError(f"{path}: missing {k}")
        for k, v in value.items():
            if k in props:
                check(props[k], v, f"{path}.{k}")
    elif t == "array":
        if not isinstance(value, list):
            raise ValueError(f"{path} must be a list")
        if not schema.get("minItems", 0) <= len(value) <= schema.get("maxItems", 10 ** 6):
            raise ValueError(f"{path} must have {schema.get('minItems', 0)}-{schema.get('maxItems')} items")
        for i, v in enumerate(value):
            check(schema["items"], v, f"{path}[{i}]")
    elif t == "string":
        if not isinstance(value, str):
            raise ValueError(f"{path} must be a string")
        if not schema.get("minLength", 0) <= len(value) <= schema.get("maxLength", 10 ** 6):
            raise ValueError(f"{path} must be {schema.get('minLength', 0)}-{schema.get('maxLength')} characters")
        if ng.CONTROL.search(value):
            raise ValueError(f"{path} contains control characters")
        if "pattern" in schema and not re.fullmatch(schema["pattern"], value):
            raise ValueError(f"{path} is not a valid value")
    elif t == "integer":
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError(f"{path} must be an integer")
        if not schema.get("minimum", -10 ** 9) <= value <= schema.get("maximum", 10 ** 9):
            raise ValueError(f"{path} must be {schema.get('minimum')}-{schema.get('maximum')}")
    elif t == "boolean":
        if not isinstance(value, bool):
            raise ValueError(f"{path} must be true or false")
    if "enum" in schema and value not in schema["enum"]:
        raise ValueError(f"{path}: {str(value)[:80]!r} is not one of {', '.join(map(str, schema['enum']))}")


def clip(text):
    if len(text) <= MAX_OUTPUT:
        return text
    half = MAX_OUTPUT // 2
    return text[:half] + f"\n...[{len(text) - MAX_OUTPUT} chars cut from the middle]...\n" + text[-half:]


def pairs(where):
    return [(c["field"], c["value"]) for c in where]


class Tools:
    """The read-only tools, bound to one es_read.Search."""

    def __init__(self, search, default_since="24h", pseudo=None):
        self.search, self.default_since = search, default_since
        self.p = pseudo or ps.Identity()  # field values get their stand-ins here; noise-agent.py does the rest

    def specs(self):
        return [{"type": "function", "function": {"name": n, **s}} for n, s in SCHEMAS.items()]

    def call(self, name, args):
        """Run one tool call from a model. Returns text; never raises for bad input."""
        if name not in SCHEMAS:
            return f"error: there is no tool {str(name)[:60]!r}; tools: {', '.join(SCHEMAS)}"
        try:
            check(SCHEMAS[name]["parameters"], args)
            return clip(getattr(self, "_" + name)(**args))
        except ValueError as e:
            return f"error: {e}"
        except SystemExit as e:  # an Elasticsearch error from es_read
            return f"error: {str(e)[:500]}"

    def _breakdown(self, where, group_by, host=None, since=None, top=10):
        since = since or self.default_since
        flt = [{"range": {"@timestamp": {"gte": f"now-{since}"}}}]
        if host:
            flt.append({"term": {"host.name": host}})
        flt += [nr.term_or_wildcard(f, v) for f, v in pairs(where)]
        res = self.search.search({"size": 0, "track_total_hits": True, "query": {"bool": {"filter": flt}},
                                  "aggs": {f: {"terms": {"field": f, "size": top}} for f in group_by}})
        total = res["hits"]["total"]["value"]
        on = f" on {self.p.value('host.name', host)}" if host else ""
        out = [f"{total:,} events over the last {since}{on} where "
               + " and ".join(f"{f}={self.p.value(f, v)}" for f, v in pairs(where))]
        for f in group_by if total else []:
            agg = res["aggregations"][f]
            covered = sum(b["doc_count"] for b in agg["buckets"]) + agg["sum_other_doc_count"]
            out.append(f"\n== {f}  ({covered / total:.0%} of events have it)")
            for b in agg["buckets"]:
                out.append(f"{b['doc_count']:>12,}  {b['doc_count'] / total:6.1%}  {self.p.value(f, b['key'])}")
            if agg["sum_other_doc_count"]:
                out.append(f"{agg['sum_other_doc_count']:>12,}  {agg['sum_other_doc_count'] / total:6.1%}  (other)")
        return "\n".join(out)

    def _count(self, os, conditions, descendants=False, since=None):
        since = since or self.default_since
        f = {"os": os, "conditions": conditions, "descendants": descendants}
        res = self.search.search({"size": 0, "track_total_hits": True, "query": ng.query(f, since), "aggs": {
            "hosts": {"terms": {"field": "host.name", "size": 10}},
            "cat": {"terms": {"field": "event.category", "size": 10}}}})
        n = res["hits"]["total"]["value"]
        out = [f"{n:,} {os} events over the last {since} match: {'children of ' if descendants else ''}"
               + " and ".join(f"{c['field']}{'~' if '*' in c['value'] or '?' in c['value'] else ''}={c['value']}"
                              for c in conditions)]
        if descendants:
            out.append("  (direct children only; deeper descendants would be filtered too)")
        for label, key in (("hosts", "hosts"), ("categories", "cat")):
            if res["aggregations"][key]["buckets"]:
                out.append(f"  {label}: " + ", ".join(f"{self.p.value('host.name', b['key']) if key == 'hosts' else b['key']} {b['doc_count']:,}"
                                                      for b in res["aggregations"][key]["buckets"]))
        return "\n".join(out)

    def _explain(self, host, where, since=None, interval="1h"):
        since = since or self.default_since
        if nr.window_seconds(since) / nr.window_seconds(interval) > MAX_BUCKETS:
            raise ValueError(f"since/interval gives more than {MAX_BUCKETS} buckets; use a longer interval")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            explain_report.run(self.search, host, pairs(where), since, interval, sample=False)
        return buf.getvalue()
