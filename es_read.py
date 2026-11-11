"""Read-only Elasticsearch access: the only network code the model steps and explain.py load.

It can do two things and nothing else: run a search on one of INDICES, and ask Elasticsearch
what the key is allowed to do (its own API key record, and _has_privileges). There is no Kibana, no other path, no other method. Writing
filters is in noise-cut.py, which the model steps never load.

Settings come from one file (ELASTIC_URL, ELASTIC_API_KEY), never from the environment.
"""
import json
import os
import re
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from noise_rules import read_env_file, read_key_file  # noqa: E402

USER_ENV = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config", "user.env")
INDICES = ("logs-*", "logs-endpoint.events.network-*")
# What each kind of key may hold, as an allowlist checked against the key's own role descriptors
# (require_key). An API key created without role descriptors has all of its owner's privileges,
# so it is refused. Then _has_privileges is asked about write privileges as a second check.
# Index privileges must be read-only; which indices doesn't matter, since search() only ever
# queries INDICES.
READ_INDEX = {"read", "view_index_metadata"}
KIBANA_APP = "kibana-.kibana"
KIBANA_READ = re.compile(r"(feature_[A-Za-z0-9]+\.(minimal_read|read|[a-z_]*_read)|read|space_read)")
# apply also needs Security event filters (and the artifact management they live in), nothing more.
KIBANA_APPLY = re.compile(r"feature_(siem|securitySolution)[A-Za-z0-9]*\.(minimal_read|minimal_all|read|"
                          r"[a-z_]*_read|event_filters_all|global_artifact_management_all)|read|space_read")
WRITE_INDEX_PRIVS = ["write", "index", "create", "create_doc", "delete", "delete_index", "manage", "all"]
WRITE_CLUSTER_PRIVS = ["all", "manage", "manage_security", "manage_api_key", "manage_own_api_key",
                       "manage_pipeline", "manage_ingest_pipelines", "manage_ilm", "manage_index_templates",
                       "manage_transform"]
WRITE_KIBANA_PRIVS = ["all", "feature_siem.all", "feature_siemV2.all", "feature_siemV3.all",
                      "feature_siem.event_filters_all", "feature_siemV2.event_filters_all",
                      "feature_siemV3.event_filters_all", "feature_fleet.all", "feature_fleetv2.all"]
SPACES = ["*", "space:default"]


class Search:
    def __init__(self, env_file=None, key_file=None):
        """Settings from env_file; the key from key_file (read.env) if given, else ELASTIC_API_KEY there."""
        self.env_file = os.path.expanduser(env_file or os.environ.get("ELASTIC_ENV_FILE") or USER_ENV)
        if not os.path.exists(self.env_file):
            sys.exit(f"{self.env_file} not found.")
        conf = read_env_file(self.env_file)
        url = conf.get("ELASTIC_URL", "")
        if key_file:
            if conf.get("ELASTIC_API_KEY"):
                sys.exit(f"{self.env_file} has an ELASTIC_API_KEY: keys go in {key_file} only.")
            if not os.path.exists(key_file):
                sys.exit(f"{key_file} not found.")
            self._key, self.key_from = read_key_file(key_file), key_file
        else:
            self._key, self.key_from = conf.get("ELASTIC_API_KEY", ""), self.env_file
        if not url.startswith("https://") or not self._key:
            sys.exit(f"Set ELASTIC_URL (https://...) in {self.env_file} and the API key in {self.key_from}.")
        self.url = url.rstrip("/")

    def _post(self, path, body, method="POST", soft=False):
        req = urllib.request.Request(self.url + path, data=None if body is None else json.dumps(body).encode(),
                                     method=method,
                                     headers={"Authorization": f"ApiKey {self._key}",
                                              "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if soft and e.code in (401, 403, 404):
                return None
            sys.exit(f"HTTP {e.code} on {method} {path.split('?')[0]}\n{e.read().decode(errors='replace')[:1000]}")

    def search(self, body, index="logs-*"):
        if index not in INDICES:
            raise ValueError(f"index {index!r} is not one of {INDICES}")
        return self._post(f"/{index}/_search?ignore_unavailable=true", body)

    # noise-cut.py's Api.es(path, body) shape, for code shared with it (search paths only).
    def es(self, path, body):
        for index in INDICES:
            if path == f"/{index}/_search?ignore_unavailable=true":
                return self.search(body, index)
        raise ValueError(f"read-only client: {path} is not a search")

    def write_privileges(self):
        """The write-type privileges this key has, e.g. ['index logs-*: write', 'kibana: all']."""
        res = self._post("/_security/user/_has_privileges", {
            "cluster": WRITE_CLUSTER_PRIVS,
            "index": [{"names": ["logs-*", ".kibana*", ".lists*", ".items*"], "privileges": WRITE_INDEX_PRIVS}],
            "application": [{"application": KIBANA_APP, "resources": SPACES, "privileges": WRITE_KIBANA_PRIVS}]})
        bad = [f"cluster: {p}" for p, ok in res.get("cluster", {}).items() if ok]
        bad += [f"index {i}: {p}" for i, ps in res.get("index", {}).items() for p, ok in ps.items() if ok]
        bad += [f"kibana: {p}" for r in res.get("application", {}).values() for ps in r.values()
                for p, ok in ps.items() if ok]
        return sorted(set(bad))

    def key_problems(self, kind):
        """Why this key holds more than a `kind` key ("read" or "apply") may, from its own API key
        record: [] if it is within the allowlist."""
        me = self._post("/_security/_authenticate", None, "GET")
        key_id = (me.get("api_key") or {}).get("id")
        if not key_id or not re.fullmatch(r"[A-Za-z0-9_-]+", key_id):
            return ["not an API key"]
        # A restricted key may not be allowed to read its own record (that needs API key privileges):
        # then _has_privileges, which every key may call, is the check.
        res = self._post(f"/_security/api_key?id={key_id}", None, "GET", soft=True)
        keys = (res or {}).get("api_keys") or []
        if len(keys) != 1:
            return self.write_privileges() if kind == "read" else [
                p for p in self.write_privileges() if not p.startswith("kibana: feature_siem") or p.endswith(".all")]
        roles = keys[0].get("role_descriptors") or {}
        if not roles:
            return ["it was created without restrictions, so it has all of its owner's privileges"]
        app_ok = KIBANA_READ if kind == "read" else KIBANA_APPLY
        bad = []
        for name, r in roles.items():
            bad += [f"{name}: cluster {p}" for p in r.get("cluster") or []]
            bad += [f"{name}: run_as" for _ in r.get("run_as") or []]
            bad += [f"{name}: remote indices" for _ in (r.get("remote_indices") or []) + (r.get("remote_cluster") or [])]
            for ix in r.get("indices") or []:
                bad += [f"{name}: index privilege {p}" for p in ix.get("privileges") or [] if p not in READ_INDEX]
            for app in r.get("applications") or []:
                if app.get("application") != KIBANA_APP:
                    bad.append(f"{name}: application {app.get('application')}")
                    continue
                bad += [f"{name}: kibana {p}" for p in app.get("privileges") or [] if not app_ok.fullmatch(p)]
        return bad + self.write_privileges() if kind == "read" else bad + [
            p for p in self.write_privileges() if not p.startswith("kibana: feature_siem") or p.endswith(".all")]

    def require_key(self, kind):
        """Stop unless the key holds no more than a `kind` key may ("read" or "apply")."""
        bad = self.key_problems(kind)
        if bad:
            need = ("index privilege 'read' on logs-* and nothing else" if kind == "read" else
                    "index privilege 'read' on logs-* and Kibana Security 'Event Filters: All' (+ 'Global "
                    "artifact management: All'), nothing else")
            sys.exit(f"The key in {self.key_from} can do more than this step needs:\n  " + "\n  ".join(bad[:12])
                     + f"\nUse an API key restricted to {need} (README, 'Keys').")

    def require_read_only(self):
        self.require_key("read")
