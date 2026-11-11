"""A local model that finds identifying values in text before it leaves for a model, with pseudo.py
as the backstop.

Each line not checked before is shown, as it is (the model is local), to a model that lists the host
names, user names, IPs, MACs, internal domains, secrets, places and organizations in it. Code checks
each one and hands it to the pseudonyms, which then replace everything: what the model named and,
as the backstop, whatever their own patterns and lists catch. Anything the model named that is still
there after that is replaced anyway. Program, script and project names are kept: they identify no
one, and the cloud model needs them.

Always local: the URL must be a private address or an internal name, never ollama.com, and the model
must be one Ollama runs itself (no `:cloud` model, which Ollama forwards to ollama.com). The model must
already be loaded; its context and keep-alive are kept, so the server is used as it is set up.
Fails closed: if the local model can't answer, the step stops before anything is sent.
"""
import datetime
import ipaddress
import json
import os
import re
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request

import pseudo as ps

HERE = os.path.dirname(os.path.abspath(__file__))
CHUNK = 3000  # characters of new lines per request: short replies, well inside any context
# A made-up line first in every request: the model must name both its names. They are new for every
# request, so a log line can't know which names to give. It also helps the model find names at all.
CANARY_LINES = ("rsync -a /srv/photos/ {user}@{host}:/backup/", "scp /srv/notes.tar.gz {user}@{host}:/archive/",
                "ssh {user}@{host} df -h /srv")
CANARY_ROLES = ("nas", "srv", "box", "vault", "backup", "store")
RANDOM = secrets.SystemRandom()


def made_up(syllables=3):
    """A pronounceable made-up name, like kobari."""
    return "".join(RANDOM.choice("bdfgklmnprstvz") + RANDOM.choice("aeiou") for _ in range(syllables))


def canary(text=""):
    """(line, (user, host)): a made-up line whose names are not already in text."""
    low = text.lower()
    while True:
        user, host = made_up(), f"{made_up()}-{RANDOM.choice(CANARY_ROLES)}"
        if user not in low and host not in low:
            return RANDOM.choice(CANARY_LINES).format(user=user, host=host), (user, host)
KINDS = ["host", "user", "ip", "mac", "domain", "secret", "place", "organization", "software"]
ADDRESS = ("ip", "mac", "secret")  # may have no letters; the patterns replace them
EXTENSION = re.compile(r"(?i)\.(?:sh|bash|py|pl|rb|js|ts|php|ps1|bat|cmd|exe|app|service|timer|conf|cfg|json|ya?ml|txt|log)$")
FORMAT = {"type": "object", "additionalProperties": False, "required": ["found"], "properties": {
    "found": {"type": "array", "maxItems": 40, "items": {
        "type": "object", "additionalProperties": False, "required": ["name", "kind"],
        "properties": {"name": {"type": "string"}, "kind": {"type": "string", "enum": KINDS}}}}}}
# A reverse-DNS app ID (com.apple.Safari, at.vendor.app.daemon): software.
BUNDLE_ID = re.compile(r"(?i)^(?:com|org|net|io|at|de|uk|fr|ch|nl|se|jp|us|co|me|app|dev)\.[\w-]+\.")
# Programs and folders: a name seen as part of one is software, not something identifying.
SYSTEM_PATH = r"(?:/(?:usr|bin|sbin|lib\w*|etc|opt|proc|sys|var/lib|System|Library|Applications|snap|nix)(?:/[^\s/'\"]+)*)/"


def local_url(url):
    """The problem with url as a local Ollama, or None."""
    u = urllib.parse.urlsplit(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        return f"{url!r} is not an http(s) URL"
    host = u.hostname.lower().rstrip(".")
    if host == "ollama.com" or host.endswith(".ollama.com"):
        return "the sanitizer must be a local Ollama, not ollama.com"
    try:
        a = ipaddress.ip_address(host)
    except ValueError:
        if "." not in host or any(host.endswith("." + t) for t in ps.INTERNAL_TLDS) or host == "localhost":
            return None
        return f"{host} is not a private address or an internal name (.lan, .local, .internal, ...)"
    if a.is_private or a.is_loopback or a.is_link_local or (a.version == 4 and a in ipaddress.ip_network("100.64.0.0/10")):
        return None
    return f"{host} is a public address; the sanitizer must be on your own network"


class Sanitizer:
    def __init__(self, url, model, timeout=600, own_text=()):
        problem = local_url(url)
        if problem:
            raise SystemExit(f"NOISE_SANITIZER_URL: {problem}")
        if model.endswith((":cloud", "-cloud")):
            raise SystemExit(f"NOISE_SANITIZER_MODEL {model!r} is a cloud model; it must run locally")
        self.url, self.model, self.timeout = url.rstrip("/"), model, timeout
        self.own = [s.lower() for s in own_text]  # this tool's own words: never replaced
        self.seen = set()  # lines already checked
        self.programs = set()  # names of programs seen in system paths: software, never replaced
        self.found, self.refused, self.software, self.seconds, self.requests = [], [], [], 0.0, 0
        self.split = self.unverified = 0  # requests split for a missing canary; lines left unverified
        self.named, self.backstop, self.said = {}, [], set()  # named per kind; caught only by the pseudonyms
        with open(os.path.join(HERE, "prompts", "sanitize.md")) as fh:
            self.system = fh.read().strip()
        self.options = None

    def _post(self, path, body, timeout=60):
        req = urllib.request.Request(self.url + path, json.dumps(body).encode(), {"content-type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r)

    def check(self):
        """The model is local and loaded. Returns a line about it."""
        show = self._post("/api/show", {"model": self.model})
        if show.get("remote_host") or show.get("remote_model"):
            raise SystemExit(f"NOISE_SANITIZER_MODEL {self.model!r} runs at {show.get('remote_host')}; it must run locally")
        with urllib.request.urlopen(self.url + "/api/ps", timeout=60) as r:
            loaded = {m["name"]: m for m in json.load(r).get("models", [])}
        m = loaded.get(self.model) or loaded.get(self.model + ":latest")
        if not m:
            raise SystemExit(f"NOISE_SANITIZER_MODEL {self.model!r} is not loaded on {self.url} "
                             f"(loaded: {', '.join(loaded) or 'none'}); load it there first")
        # Ask with the settings it was loaded with, so Ollama doesn't load it again with others.
        exp = datetime.datetime.fromisoformat(re.sub(r"\.\d+", "", m["expires_at"]))
        forever = exp.year > 2100
        self.options = {"num_ctx": m["context_length"]}
        self.keep_alive = -1 if forever else None
        return f"{self.model} on {self.url}, context {m['context_length']:,}, {'kept loaded' if forever else 'expires ' + m['expires_at']}"

    def names(self, lines):
        """(value, kind) the model finds in some lines (as it wrote them, not yet checked), and whether it
        named the canary's names: if not, the answer can't be trusted."""
        line, canary_names = canary("\n".join(lines))
        body = {"model": self.model, "stream": False, "format": FORMAT, "options": {**self.options, "temperature": 0, "seed": 1},
                "messages": [{"role": "system", "content": self.system},
                             {"role": "user", "content": "\n".join([line] + list(lines))}]}
        if self.keep_alive is not None:
            body["keep_alive"] = self.keep_alive
        t = time.time()
        try:
            res = self._post("/api/chat", body, self.timeout)
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise SystemExit(f"The sanitizer at {self.url} did not answer ({e}); nothing was sent.") from None
        self.seconds += time.time() - t
        self.requests += 1
        try:
            found = json.loads(res["message"]["content"]).get("found", [])
        except (ValueError, KeyError, AttributeError):
            raise SystemExit("The sanitizer's answer was not the JSON asked for; nothing was sent.") from None
        names = []
        for v in found if isinstance(found, list) else []:
            if not isinstance(v, dict) or not isinstance(v.get("name"), str):
                continue
            kind = v.get("kind") if v.get("kind") in KINDS else "host"
            if kind == "software":  # kept: the cloud model needs program names to judge the noise
                self.software.append(v["name"])
            else:
                names.append((EXTENSION.sub("", v["name"].strip()), kind))  # garden-cam.sh: garden-cam
        low = {n.lower() for n, _ in names}
        return [(n, k) for n, k in names if n.lower() not in canary_names], all(c in low for c in canary_names)

    def why_not(self, value, kind, text):
        """Why a value the model gave is not used, or None. text: the lines it was found in."""
        v = value.strip()
        low = v.lower()
        if len(v) < 3 or len(v) > 200 or (kind not in ADDRESS and not re.search(r"[A-Za-z]", v)):
            return "too short, too long or no letters"
        if kind not in ADDRESS and re.search(r"[\s/\\=@'\"]", v):
            return "not a single name"
        if ps.FAKE.match(low) or re.search(ps.STAND_IN, low):
            return "a stand-in"
        if BUNDLE_ID.match(v):
            return "an app ID"
        if low in ps.SYSTEM_USERS or any(low == d or low.endswith("." + d) for d in ps.VENDOR_DOMAINS):
            return "a system account or a vendor"
        if not re.search(rf"(?<![A-Za-z]){re.escape(v)}(?![A-Za-z])", text, re.I):
            return "not in the text"
        if re.search(rf"{SYSTEM_PATH}(?:[^\s/'\"]*/)*[^\s/'\"]*(?<![A-Za-z]){re.escape(v)}(?![A-Za-z])", text, re.I):
            return "part of a system path"
        if low in self.programs or low.rsplit(".", 1)[0] in self.programs:
            return "a program"
        if any(re.search(rf"(?<![a-z]){re.escape(low)}(?![a-z])", s) for s in self.own):
            return "in this tool's own text"
        return None

    def clean(self, text, p):
        """text (real, not yet pseudonymized) with the pseudonyms applied, the names the model finds among
        its new lines included."""
        self.programs.update(m.lower().rsplit(".", 1)[0] if "." in m[1:] else m.lower()
                             for m in re.findall(rf"{SYSTEM_PATH}(?:[^\s/'\"]+/)*([^\s/'\"]+)", str(text)))
        new = [line for line in dict.fromkeys(str(text).splitlines())
               if line.strip() and line not in self.seen and re.search(r"[A-Za-z]{3}", line)]
        chunks, cur = [], []
        # a long line goes in pieces that overlap a little, so no name is cut in two unseen
        pieces = [line[i:i + CHUNK] for line in new for i in range(0, len(line), CHUNK - 100)]
        for line in pieces:
            if cur and sum(len(x) + 1 for x in cur) + len(line) > CHUNK:
                chunks.append(cur)
                cur = []
            cur.append(line)
        if cur:
            chunks.append(cur)
        added, named = [], []

        def look(lines):
            joined = "\n".join(lines)
            names, ok = self.names(lines)
            # The canary's names missing: a line may have told the model to say nothing. Halves are
            # checked again, so such a line only hides what is in itself.
            if not ok and len(lines) > 1:
                self.split += 1
                look(lines[:len(lines) // 2])
                look(lines[len(lines) // 2:])
                return
            if not ok:
                self.unverified += 1
            for v, kind in dict.fromkeys(names):
                why = self.why_not(v, kind, joined)
                if why:
                    self.refused.append((v, why))
                    continue
                named.append((v, kind))
        for lines in chunks:
            look(lines)
        self.seen.update(new)
        # What the pseudonyms alone would leave: anything named there is new to them.
        before = p.text(text)
        for v, kind in named:
            self.named[kind] = self.named.get(kind, 0) + 1
            if kind == "user":
                p.add_user(v)
            elif kind == "domain" and "." in v:
                p.add_domain(v)
            elif kind not in ADDRESS:
                p.listed.add(v.lower())  # hosts, places, organizations: wherever no letter touches them
        out = p.text(text)
        for v, kind in named:
            edge = (r"(?<![\w.:])", r"(?![\w:]|\.\d)") if kind in ADDRESS else (r"(?<![A-Za-z])", r"(?![A-Za-z])")
            gone = lambda s, v=v, edge=edge: not re.search(edge[0] + re.escape(v) + edge[1], s, re.I)
            if not gone(out):  # still there: replaced anyway
                p.listed.add(v.lower())
                out = p.text(text)
            if not gone(out) or gone(before):
                continue
            added.append(v)
        # The backstop: real values the pseudonyms replaced that the model didn't name.
        self.said |= {v.lower() for v, _ in named}
        said = self.said
        self.backstop += sorted({r for f, r in p.real.items() if f in out and str(r).lower() not in said
                                 and str(r) in str(text)})
        self.found += added
        return out, added
