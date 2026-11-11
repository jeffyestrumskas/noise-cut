"""Pseudonyms for what leaves this machine for a model (noise-agent.py).

Before any text goes to a model, identifying values in it are replaced with stand-ins; when the model
calls a tool or submits a filter, code puts the real values back. The table lives only in memory, in
this process; models never see it. Stand-ins are numbered in the order values are first seen, so they
carry nothing of the real value (unlike a hash, which could be reversed by trying every IP or name).

  internal host names   nas.example.lan -> host-1.lan, nas -> host-1
  internal domains      corp.example.com -> site-1.lan, anything.corp.example.com -> host-2.lan (anywhere)
  listed host names     nas -> value-1 wherever no letter touches it: backup-nas.sh -> backup-value-1.sh,
                        nas2 -> value-12, but not canasta
  real user names       /home/alice -> /home/user-1   (root and system accounts are kept)
  private IPs           10.1.2.3 -> 198.18.0.1        (RFC 1918, 100.64/10, IPv6 ULA -> 2001:db8:a::1)
  public IPs            8.8.8.8 -> 240.0.0.1          (IPv6 -> 2001:db8:b::1)
  external domains      host.example.org -> domain-1.org   (well-known vendors are kept)
  secrets               --token=abc123... -> --token=secret-1
  MAC addresses         aa:bb:cc:dd:ee:ff -> 02:00:00:00:00:01
  numbers in URL paths  /orgs/123456789/ -> /orgs/900000001/,  query strings -> ?query-1
198.18.0.0/15, 240.0.0.0/4 and 2001:db8::/32 are reserved ranges that never appear in real traffic.
"""
import ipaddress
import os
import re

# Kept as they are: they carry meaning and identify no one.
SYSTEM_USERS = {
    "root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news", "uucp", "proxy", "www-data",
    "backup", "list", "irc", "gnats", "nobody", "nogroup", "sshd", "messagebus", "syslog", "polkitd", "avahi",
    "colord", "rtkit", "gdm", "sddm", "lightdm", "postfix", "dnsmasq", "ntp", "chrony", "_apt", "uuidd",
    "tcpdump", "tss", "usbmux", "kernoops", "pulse", "geoclue", "saned", "cups-pk-helper", "fwupd-refresh",
    "dhcpcd", "landscape", "lxd", "snap_daemon", "docker", "system", "local system", "local service",
    "network service", "-", "n/a",
    # service accounts named after their software
    "grafana", "prometheus", "postgres", "mysql", "redis", "nginx", "influxdb", "mosquitto", "nut", "ollama",
    "elastic-agent", "elasticsearch", "kibana", "node-exporter", "node_exporter", "jellyfin", "plex", "syncthing"}
# A real account with a common word for a name: only replaced where it is clearly a user name.
WORDS = {"user", "admin", "guest", "test", "dev", "pi", "ubuntu", "debian", "app", "service", "default", "data"}
VENDOR_DOMAINS = {
    "apple.com", "icloud.com", "icloud-content.com", "mzstatic.com", "apple-cloudkit.com", "aaplimg.com",
    "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "gvt1.com", "microsoft.com",
    "windows.com", "windowsupdate.com", "live.com", "office.com", "azure.com", "msftconnecttest.com",
    "amazonaws.com", "cloudfront.net", "akamai.net", "akamaiedge.net", "akamaized.net", "cloudflare.com",
    "fastly.net", "github.com", "githubusercontent.com", "ubuntu.com", "canonical.com", "snapcraft.io",
    "debian.org", "docker.com", "docker.io", "elastic.co", "elastic-cloud.com", "cloud.es.io", "brave.com",
    "bravesoftware.com", "mozilla.org", "mozilla.com", "autodesk.com", "adobe.com", "ollama.com",
    "anthropic.com", "claude.ai", "tailscale.com", "letsencrypt.org", "ntp.org", "duckduckgo.com",
    "obdev.at", "safebrowsing.apple"}
INTERNAL_TLDS = ("lan", "local", "internal", "home.arpa", "localdomain", "intranet", "corp", "home", "ts.net")

IPV4 = re.compile(r"(?<![\w.])(?<!ver=)(?<!version=)((?:\d{1,3}\.){3}\d{1,3})(?![\w.]*\d)")
IPV6 = re.compile(r"(?<![\w:.])([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})(?![\w:])")
MAC = re.compile(r"(?<![\w:])((?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})(?![\w:])")
SECRET = re.compile(
    r"(?i)((?:token|secret|passw(?:or)?d?|pwd|api[_-]?key|apikey|auth(?:orization)?|bearer|access[_-]?key|"
    r"session|cookie|credential)[\w-]*\s*[=:]\s*(?:bearer\s+|basic\s+)?['\"]?|bearer\s+|basic\s+)"
    r"([^\s'\"&,;]{8,})"
    r"|\b(eyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]{10,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}|"
    r"github_pat_\w{30,}|sk-[A-Za-z0-9_-]{20,}|xox[abpr]-[\w-]{10,}|glpat-[\w-]{20,})")
URL = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)([^/\s'\"?#]+)([^\s'\"?#]*)(\?[^\s'\"#]*)?")
HOME = re.compile(r"(/home/|/Users/|/var/home/|C:\\Users\\)([^/\\\s'\"*?]+)")
AT_USER = re.compile(r"(?<![\w.+-])([A-Za-z_][\w.-]{0,31})@([A-Za-z0-9][\w.-]*)")
FLAG_USER = re.compile(r"((?:^|\s)(?:-l|-u|--user|--username|--login)[ =])([A-Za-z_][\w.-]{0,31})")
SEP = r"(?:\\*\.|\[\.\])"  # a dot, also written as a regex (\.) or defanged ([.])
STAND_IN = r"(?:host|site|value|user|domain|secret|query)-\d+(?:\.[A-Za-z]+)?"
FAKE = re.compile(r"^(host|site|value|user|domain|secret|query)-\d+|^198\.1[89]\.|^240\.|^2001:db8:|^02:00:00:")
USER_FIELDS = ("user.name",)
HOST_FIELDS = ("host.name", "host.hostname", "observer.hostname")
DOMAIN_FIELDS = ("destination.domain", "dns.question.name", "url.domain", "source.domain")


class Pseudonyms:
    def __init__(self, domains=(), hosts=()):
        self.fake, self.real, self.n = {}, {}, {}
        self.users, self.hosts, self.suffixes, self.domains, self.listed = set(), set(), set(), set(), set()
        for d in domains:
            self.add_domain(d)
        for h in hosts:
            self.add_host(h)
            h = h.strip().lower().rstrip(".")
            if h and not FAKE.match(h):  # replaced wherever no letter touches it (see scrub)
                self.listed.update({h, h.split(".")[0]})

    # ------------------------------------------------------------ the table
    def _issue(self, kind, real, make, key=None):
        key = (kind, real if key is None else key)
        if key not in self.fake:
            self.n[kind] = self.n.get(kind, 0) + 1
            fake = make(self.n[kind])
            while fake in self.real:  # never two real values behind one stand-in
                self.n[kind] += 1
                fake = make(self.n[kind])
            self.fake[key], self.real[fake] = fake, real
        return self.fake[key]

    def seed(self, search, since):
        """Learn the real user and host names first, so they are replaced wherever they turn up."""
        res = search.search({"size": 0, "query": {"range": {"@timestamp": {"gte": f"now-{since}"}}},
                             "aggs": {"u": {"terms": {"field": "user.name", "size": 1000}},
                                      "h": {"terms": {"field": "host.name", "size": 1000}}}})
        for b in res["aggregations"]["u"]["buckets"]:
            self.add_user(str(b["key"]))
        for b in res["aggregations"]["h"]["buckets"]:
            self.add_host(str(b["key"]))
        return self

    def add_user(self, u):
        if u and u.lower() not in SYSTEM_USERS and not u.startswith("_") and not u.isdigit() and not FAKE.match(u):
            self.users.add(u)

    def add_host(self, h):
        h = h.strip().lower().rstrip(".")
        if h and not FAKE.match(h):
            self.hosts.add(h)
            if "." in h:
                self.hosts.add(h.split(".")[0])
                self.suffixes.add(h.split(".", 1)[1])
                if "." in h.split(".", 1)[1]:  # nas.corp.example.com: corp.example.com is internal too
                    self.add_domain(h.split(".", 1)[1])

    def add_domain(self, d):
        """An internal domain: it and every name under it are replaced wherever they turn up."""
        d = d.strip().lower().strip(".")
        if "." in d and not FAKE.match(d) and not any(d == v or d.endswith("." + v) for v in VENDOR_DOMAINS):
            self.domains.add(d)
            self.suffixes.add(d)

    # ------------------------------------------------------------ one value
    def user(self, u):
        if u.lower() in SYSTEM_USERS or u.startswith("_") or u.isdigit() or FAKE.match(u):
            return u
        self.users.add(u)
        return self._issue("user", u, lambda n: f"user-{n}")

    def host(self, h):
        if FAKE.match(h):
            return h
        low = h.lower().rstrip(".")
        short, _, suffix = low.partition(".")
        if short in self.listed:  # a name you listed: value-N, one per spelling, so it comes back as it was
            low = h.rstrip(".")
            base = self._issue("value", low.split(".")[0], lambda n: f"value-{n}")
        else:
            base = self._issue("host", h.rstrip(".").split(".")[0], lambda n: f"host-{n}", key=short)
        if not suffix:
            return base
        tld = next((t for t in INTERNAL_TLDS if suffix == t or suffix.endswith("." + t)), "lan")
        # The same number as the short name, so the model sees they are one host.
        return self._issue("fqdn", h.rstrip("."), lambda n: f"{base}.{tld}" if n == 1 or f"{base}.{tld}" not in
                           self.real else f"{base}-{n}.{tld}", key=low)

    def domain(self, d):
        low = d.lower().rstrip(".")
        if low in self.domains:
            return self._issue("site", low, lambda n: f"site-{n}.lan")
        if FAKE.match(low) or self.internal(low):
            return self.host(d) if not FAKE.match(low) else d
        labels = low.split(".")
        if len(labels) < 2 or any(low == v or low.endswith("." + v) for v in VENDOR_DOMAINS):
            return d
        return self._issue("domain", low, lambda n: f"domain-{n}.{labels[-1]}")

    def internal(self, name):
        low = name.lower().rstrip(".")
        return (low in self.hosts or any(low == s or low.endswith("." + s) for s in self.suffixes)
                or any(low.endswith("." + t) for t in INTERNAL_TLDS))

    def ip(self, s):
        try:
            a = ipaddress.ip_address(s)
        except ValueError:
            return s
        if a.is_loopback or a.is_unspecified or a.is_multicast or a.is_link_local or FAKE.match(str(a)):
            return s
        private = a.is_private or (a.version == 4 and a in ipaddress.ip_network("100.64.0.0/10"))
        if a.version == 4:
            base = "198.18.0.0" if private else "240.0.0.0"
            return self._issue("ip4p" if private else "ip4", str(a),
                               lambda n: str(ipaddress.ip_address(base) + n))
        return self._issue("ip6p" if private else "ip6", str(a),
                           lambda n: str(ipaddress.ip_address("2001:db8:a::" if private else "2001:db8:b::") + n))

    def value(self, field, v):
        """A field's whole value, e.g. a breakdown bucket key."""
        v = str(v)
        if field in USER_FIELDS:
            return self.user(v)
        if field in HOST_FIELDS:
            return self.host(v)
        if field in DOMAIN_FIELDS:
            return self.domain(v)
        return self.text(v)

    # ------------------------------------------------------------ free text
    def text(self, s):
        """Every identifying value inside a string (command lines, paths, tool output, JSON)."""
        s = str(s)
        s = SECRET.sub(self._secret, s)
        s = URL.sub(self._url, s)
        s = MAC.sub(lambda m: self._issue("mac", m[1], lambda n: "02:00:00:%02x:%02x:%02x" % (
            n >> 16 & 255, n >> 8 & 255, n & 255), key=m[1].lower()), s)
        s = IPV4.sub(lambda m: self.ip(m[1]), s)
        s = IPV6.sub(lambda m: self.ip(m[1]) if m[1].count(":") >= 2 else m[1], s)
        s = HOME.sub(lambda m: m[1] + self.user(m[2]), s)
        s = AT_USER.sub(self._at, s)
        s = FLAG_USER.sub(lambda m: m[1] + (self.user(m[2]) if m[2] in self.users else m[2]), s)
        for name in sorted(self.hosts - self.listed, key=len, reverse=True):  # listed ones: see scrub
            s = re.sub(rf"(?<![\w.@-]){re.escape(name)}(?:\.[A-Za-z0-9-]+)*(?![\w-])",
                       lambda m, name=name: self.host(m[0]) if self.internal(m[0])
                       else self.host(m[0][:len(name)]) + m[0][len(name):], s, flags=re.I)
        for t in INTERNAL_TLDS:
            s = re.sub(rf"(?<![\w.@/-])[A-Za-z0-9][\w-]*(?:\.[\w-]+)*\.{re.escape(t)}(?![\w.-])",
                       self._internal, s, flags=re.I)
        for u in sorted(self.users, key=len, reverse=True):
            if u.lower() not in WORDS and len(u) >= 3:
                s = re.sub(rf"(?<![\w./@-]){re.escape(u)}(?![\w-])", lambda m: self.user(m[0]), s)
        return self.scrub(s)

    def scrub(self, x):
        """Every internal domain, anywhere, even joined to other text (backup-corp.example.com_old ->
        backup-site-1.lan_old), and every listed host name that no letter touches: digits, _ - . and
        the like may (backup-nas.sh -> backup-value-1.sh, NAS_old -> value-1_old), so whole words that
        contain one (canasta for "nas") are left alone.
        Last, so no other pass sees its stand-ins; noise-agent.py runs it again on every message it sends."""
        x = str(x)
        for d in sorted(self.domains, key=len, reverse=True):
            dom = SEP.join(re.escape(label) for label in d.split("."))
            x = re.sub(rf"(?:[A-Za-z0-9-]+{SEP})*{dom}", self._internal, x, flags=re.I)
        if self.listed:  # stand-ins are matched first and kept, so a name is never replaced inside one
            names = "|".join(re.escape(h) for h in sorted(self.listed, key=len, reverse=True))
            x = re.sub(rf"({STAND_IN})|(?<![A-Za-z])({names})(?![A-Za-z])", self._listed, x, flags=re.I)
        return x

    def _listed(self, m):
        return m[1] or self.host(m[2])

    def _internal(self, m):
        name = re.sub(SEP, ".", m[0])
        low = name.lower()
        if low in self.domains:
            return self._issue("site", low, lambda n: f"site-{n}.lan")
        return self.host(name)

    def _secret(self, m):
        if m[3]:
            return self._issue("secret", m[3], lambda n: f"secret-{n}")
        return m[1] + self._issue("secret", m[2], lambda n: f"secret-{n}")

    def _url(self, m):
        scheme, netloc, path, query = m[1], m[2], m[3] or "", m[4] or ""
        cred, _, hostport = netloc.rpartition("@")
        host, port = hostport, ""
        if hostport.startswith("["):
            host, _, port = hostport[1:].partition("]")
            host = "[" + self.ip(host) + "]"
        else:
            if hostport.count(":") == 1:
                host, port = hostport.split(":")
                port = ":" + port
            host = self.ip(host) if re.fullmatch(r"[\d.]+", host) else self.domain(host)
        if cred:
            user, _, pw = cred.partition(":")
            cred = self.user(user) + (":" + self._issue("secret", pw, lambda n: f"secret-{n}") if pw else "") + "@"
        path = re.sub(r"(?<=/)(\d{4,})(?=/|$)",
                      lambda x: self._issue("num", x[1], lambda n: "9" + str(n).zfill(len(x[1]) - 1)), path)
        if query:
            query = "?" + self._issue("query", query[1:], lambda n: f"query-{n}")
        return scheme + cred + host + port + path + query

    def _at(self, m):
        user, host = m[1], m[2]
        if self.internal(host) or user in self.users:
            return self.user(user) + "@" + (self.host(host) if self.internal(host) else host)
        return m[0]

    # ------------------------------------------------------------ back to real
    def back(self, x):
        """Real values for the stand-ins in what a model sent (tool arguments, submitted filters, notes)."""
        if isinstance(x, dict):
            return {k: self.back(v) for k, v in x.items()}
        if isinstance(x, list):
            return [self.back(v) for v in x]
        if not isinstance(x, str) or not self.real:
            return x
        rx = re.compile(r"(?<![\w.-])(" + "|".join(re.escape(f) for f in sorted(self.real, key=len, reverse=True))
                        + r")(?![\w-]|\.\d)")
        x = rx.sub(lambda m: self.real[m[1]], x)
        # IPV4 and IPV6 also replace a value after a "-" (the version in s6-2.11.3.2), so their stand-ins come back there too.
        ips = [f for f in self.real if re.fullmatch(r"\d+(?:\.\d+){3}|[0-9a-f]*:[0-9a-f:]+", f)]
        if ips:
            x = re.sub(r"(?<=-)(" + "|".join(re.escape(f) for f in sorted(ips, key=len, reverse=True)) + r")(?![\w:]|\.\d)",
                       lambda m: self.real[m[1]], x)
        # Internal domains and listed host names may be joined to other text (see scrub).
        joined = [f for f in self.real if f.startswith(("site-", "value-"))]
        if joined:
            # longest first, so value-12 wins over value-1 and mail2 -> value-52 comes back
            x = re.sub("(" + "|".join(re.escape(f) for f in sorted(joined, key=len, reverse=True)) + ")",
                       lambda m: self.real[m[1]], x)
        return x

    def note(self):
        """What the model is told about the stand-ins: prompts/pseudonyms.md."""
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "prompts", "pseudonyms.md")) as fh:
            return fh.read().strip()


class Identity:
    """No pseudonyms (for tests and tools run by a person)."""

    def text(self, s):
        return str(s)

    def value(self, field, v):
        return str(v)

    def back(self, x):
        return x

    def scrub(self, x):
        return x

    def note(self):
        return ""

