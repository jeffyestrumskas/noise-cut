"""The code checks every proposed filter must pass, in propose, validate and apply.

Stricter than Human mode, because no person looks at each filter:
  - one condition pins a specific program: a full path or exact command line, not a shell,
    interpreter, supervisor or everyday tool (a shell only running an absolute script);
  - a LOL binary (safety.json lolbins) only by its exact command line, and a shell or tool
    not by its parent alone;
  - an exact, known event.category (unless descendants); a * only for one whole folder;
  - no user-writable, container or relative paths (anywhere in a command line), no persistence locations;
  - no process IDs (vmmap 129, lsof -p 42, /proc/42/): they change on every restart;
  - never a debugger or memory reader (safety.json attacker_tools), not even by exact command line;
  - no program that isn't a file on disk (memfd, /proc, /dev, a deleted binary): its path says nothing
    about what runs;
  - no hiding of file activity on persistence, credential or log locations (EVIDENCE), checked against
    the files the filter actually matches, not just its own conditions;
  - a tampering action (safety.json pinned_actions, e.g. ptrace) only with both the program and its
    parent pinned, never as descendants;
  - the process itself pinned, not just its parent: a parent alone hides whatever it starts later;
  - no network destination in a command line (URL, IP, user@host, host:path, domain): beacons and
    healthchecks are fixed at the source;
  - a descendants filter only for a parent that doesn't start shells, interpreters or attacker tools.
"""
import fnmatch
import hashlib
import json
import os
import re
import shlex
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.dirname(HERE)]  # this folder, and the shared code one up
import noise_rules as nr  # noqa: E402

OS_TYPES = ("linux", "macos", "windows")
# The only fields a filter condition may use. Anything else is refused.
FILTER_FIELDS = ("process.executable", "process.command_line", "process.name",
                 "process.parent.executable", "process.parent.command_line", "process.parent.name",
                 "event.category", "event.action", "file.path", "file.name", "dll.path",
                 "dns.question.name", "destination.ip", "destination.port", "source.port",
                 "process.Ext.memfd.name", "process.Ext.memfd.flag_noexec_seal")
BOOLEAN_FIELDS = ("process.Ext.memfd.flag_noexec_seal",)  # Elastic matches only "true" or "false"
PATH_FIELDS = ("process.executable", "process.command_line", "process.parent.executable",
               "process.parent.command_line", "file.path", "dll.path")
CATEGORIES = ("process", "file", "network", "library", "registry", "dns", "authentication", "session",
              "driver", "api")
# Never filtered: hiding these hides persistence or credential access.
PERSISTENCE = re.compile(r"(/\.ssh/|authorized_keys|/etc/|/cron|/systemd/|LaunchAgents|LaunchDaemons|"
                         r"\\Start Menu\\|\\Startup\\|\\System32\\Tasks|\.bashrc|\.profile|\.zshrc|"
                         r"/init\.d/|/rc\.local|sudoers|/pam\.d/|\.plist$)", re.I)
# Files whose changes, reads or removal are persistence, credential access or wiped evidence. A filter
# that would hide file events on any of these is refused, whatever its own conditions say: count_events
# counts every matched event on them (not a top-N), from file.path or a rename's original path.
# Globs, case-insensitive: * is any run of characters (including /), ? one character.
EVIDENCE = (
    # accounts, sudo, PAM, SSH
    "*/etc/passwd*", "*/etc/shadow*", "*/etc/gshadow*", "*/etc/group*", "*/etc/sudoers*", "*/etc/doas.conf",
    "*/etc/pam.d/*", "*/etc/pam.conf", "*/etc/security/*", "*/security/pam_*", "*/.ssh/*", "*/etc/ssh/*",
    "*/var/db/dslocal/*",
    # loader, cron/at, services, boot, modules, shell startup
    "*/etc/ld.so.preload", "*/etc/ld.so.conf*", "*/etc/cron*", "*/var/spool/cron/*", "*/var/spool/at/*",
    "*/etc/anacrontab", "*/systemd/system/*", "*/systemd/user/*", "*/etc/init.d/*", "*/etc/init/*",
    "*/etc/rc.local", "*/etc/rc?.d/*", "*/etc/xdg/autostart/*", "*/.config/autostart/*", "*/etc/update-motd.d/*",
    "*/etc/modules", "*/etc/modules-load.d/*", "*/etc/modprobe.d/*", "*/udev/rules.d/*", "*/etc/profile",
    "*/etc/profile.d/*", "*/etc/bash.bashrc", "*/etc/environment", "*/etc/zsh/*", "*/etc/zshrc", "*/.bashrc",
    "*/.bash_profile", "*/.bash_login", "*/.bash_logout", "*/.profile", "*/.zshrc", "*/.zshenv", "*/.zprofile",
    "*/.zlogin",
    # macOS persistence and secrets
    "*/Library/LaunchAgents/*", "*/Library/LaunchDaemons/*", "*/Library/StartupItems/*", "*/Library/Keychains/*",
    "*/Library/Security/SecurityAgentPlugins/*", "*/com.apple.TCC/*", "*/com.apple.backgroundtaskmanagement*",
    "*/com.apple.loginwindow*", "*/etc/periodic/*", "*/etc/emond.d/*",
    # credentials and secrets
    "*/.aws/*", "*/.azure/*", "*/.config/gcloud/*", "*/.kube/config", "*/.docker/config.json", "*/.gnupg/*",
    "*/.netrc", "*/.pgpass", "*/.git-credentials", "*/.env", "*/etc/krb5.keytab", "*/krb5cc*",
    # logs and audit trails an attacker wipes
    "*/var/log/auth.log*", "*/var/log/secure*", "*/var/log/audit/*", "*/var/log/wtmp*", "*/var/log/btmp*",
    "*/var/log/lastlog", "*/var/log/faillog", "*/var/log/sudo*", "*/run/utmp", "*/var/audit/*", "*_history",
    "*/.history", "*/etc/audit/*", "*/etc/rsyslog.conf", "*/etc/rsyslog.d/*",
    # Windows
    "*\\System32\\config\\SAM*", "*\\System32\\config\\SECURITY*", "*\\NTDS\\*", "*\\winevt\\Logs\\*",
    "*\\System32\\Tasks\\*", "*\\Windows\\Tasks\\*", "*\\Start Menu\\Programs\\Startup\\*", "*\\Microsoft\\Protect\\*",
    "*\\Microsoft\\Credentials\\*", "*\\Microsoft\\Vault\\*", "*\\PSReadLine\\*", "*lsass*.dmp",
    "*\\System32\\GroupPolicy\\*", "*\\drivers\\etc\\hosts")
EVIDENCE_RE = re.compile("|".join(f"(?:{fnmatch.translate(g)})" for g in EVIDENCE), re.I | re.S)
EVIDENCE_FIELDS = ("file.path", "file.Ext.original.path")
# A program that isn't a file on disk: memfd_create, /proc/self/fd/3, /proc/1234/exe, /dev/shm/x, a deleted
# binary ("/usr/sbin/x (deleted)"). Its path doesn't say what runs, and a deleted one is gone on restart.
FILELESS = re.compile(r"^(/memfd:|memfd:|/proc/|/dev/|/run/shm/|/[^ ]*/memfd:)|\(deleted\)$", re.I)
MAX_CONDITIONS = 8
# A burst isn't steady noise (prompts/rules.md): refuse a filter whose events mostly fall in one hour,
# or in only a few hours of the window. Checked for windows of 12h or more.
BURST_SHARE = 0.5
MIN_HOURS = 3
MAX_VALUE = 2000
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
# A network destination in a command line: a URL, an IP, user@host, host:path or host:port, a domain.
# File names that look like domains (job.sh, app.conf) are not destinations.
DESTINATIONS = (re.compile(r"^[a-z][a-z0-9+.-]*://", re.I),                        # https://, rsync://
                re.compile(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$"),                       # 10.1.2.3, 10.1.2.3:80
                re.compile(r"^\[?([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\]?(:\d+)?$", re.I),  # fe80::1, [::1]:443
                re.compile(r"^[^\s/@=]+@[\w.-]+"),                                    # user@host
                re.compile(r"^[a-z][\w-]*(\.[\w-]+)*:(\d+|/|$)", re.I),                 # host:8080, host:/path
                re.compile(r"^([a-z0-9-]+\.)+[a-z]{2,24}\.?$", re.I))                    # c2.example.com
FILE_TYPES = frozenset("""sh bash py pl rb js ts php lua jar war conf cfg cnf ini toml yaml yml json xml txt log
    md csv tsv html htm css pid sock lock service timer socket target mount desktop plist so dll exe bin
    dat db sqlite gz tgz xz bz2 zst zip tar deb rpm iso img png jpg jpeg gif svg webp mp3 mp4 mkv pdf pem
    crt key pub asc sig d tmp bak old swp""".split())


def to_entries(f):
    """A proposed filter's conditions as event filter entries. Raises ValueError if malformed.
    A value with * or ? is a wildcard; anything else is an exact match."""
    if not isinstance(f, dict):
        raise ValueError("a filter must be an object")
    if f.get("os") not in OS_TYPES:
        raise ValueError(f"os must be one of {', '.join(OS_TYPES)}")
    conds = f.get("conditions")
    if not isinstance(conds, list) or not 1 <= len(conds) <= MAX_CONDITIONS:
        raise ValueError(f"conditions must be a list of 1 to {MAX_CONDITIONS}")
    entries, seen = [], set()
    for c in conds:
        if not isinstance(c, dict) or set(c) - {"field", "value", "wildcard"}:
            raise ValueError(f"a condition is {{field, value}}, got {str(c)[:200]}")
        field, value = c.get("field"), c.get("value")
        if field not in FILTER_FIELDS:
            raise ValueError(f"field {str(field)[:80]!r} is not allowed; allowed: {', '.join(FILTER_FIELDS)}")
        if not isinstance(value, str) or not value.strip() or len(value) > MAX_VALUE or CONTROL.search(value):
            raise ValueError(f"{field}: value must be 1-{MAX_VALUE} printable characters")
        if field in BOOLEAN_FIELDS and value not in ("true", "false"):
            raise ValueError(f"{field}: value must be true or false")
        if field in seen:
            raise ValueError(f"{field} appears twice")
        seen.add(field)
        wild = "*" in value or "?" in value
        entries.append({"field": field, "operator": "included", "type": "wildcard" if wild else "match",
                        "value": value})
    return entries


def canonical(f):
    """What a filter does, as data: os, descendants and its conditions. Notes are not part of it."""
    return {"os": f.get("os"), "descendants": bool(f.get("descendants")),
            "conditions": [{"field": e["field"], "value": e["value"]} for e in to_entries(f)]}


def fingerprint(f):
    """Hash of canonical(f). A verdict is bound to it: apply creates only the exact filter approved."""
    return hashlib.sha256(json.dumps(canonical(f), sort_keys=True).encode()).hexdigest()


def contains(broad, narrow):
    """True if narrow has every condition of broad (same os and descendants), so it only matches
    events broad matches too. Apply keeps the narrower one: an attacker has less to hide behind."""
    b, n = canonical(broad), canonical(narrow)
    pairs = lambda c: {(e["field"], e["value"]) for e in c["conditions"]}  # noqa: E731
    return (b["os"], b["descendants"]) == (n["os"], n["descendants"]) and pairs(b) <= pairs(n)


def wildcard_problem(field, value):
    """'' if every * and ? stands for one whole folder at least two folders deep, else why not."""
    if "*" not in value and "?" not in value:
        return ""
    if field not in PATH_FIELDS or "?" in value:
        return f"{field}: no wildcards here (only * for an entire folder in a path)"
    for m in re.finditer(r"\*", value):
        before, after = value[:m.start()], value[m.end():]
        sep = before[-1:] if before[-1:] in ("/", "\\") else None
        if not sep or not after.startswith(sep):
            return f"{field}: * may only stand for one entire folder, like /snap/app/*/bin/app"
        if len([x for x in re.split(r"[/\\]", before.split(" ")[-1]) if x]) < 2:
            return f"{field}: * must come after at least two literal folders"
    return ""


def specific(e, descendants=False):
    """True if this condition pins events to one specific program (see the module docstring)."""
    field, value = e["field"], e["value"]
    if field not in PATH_FIELDS[:4] or wildcard_problem(field, value):
        return False
    risky = nr.SHELLS | nr.SUPERVISORS | nr.ATTACKER_TOOLS | nr.COMMON_TOOLS | nr.INTERPRETERS
    if field.endswith("executable"):
        return (bool(re.match(r"(/|[A-Za-z]:\\)", value)) and not FILELESS.search(value)
                and nr.basename(value).lower() not in risky | nr.LOLBINS)
    try:
        argv = shlex.split(value)
    except ValueError:
        return False
    if not argv or not re.match(r"(/|[A-Za-z]:\\)", argv[0]):
        return False  # a bare program name: any program of that name matches
    if FILELESS.search(argv[0]) or FILELESS.search(value):
        return False  # not a file on disk, or "/usr/sbin/x (deleted)" as a command line
    name = nr.basename(argv[0]).rstrip(":").lower()
    if name in nr.LOLBINS and name not in risky:
        return "*" not in value and "?" not in value  # a living-off-the-land binary: exact command line only
    if name not in risky:
        return True
    if name in nr.SUPERVISORS or name in nr.ATTACKER_TOOLS or name in nr.COMMON_TOOLS:
        return False
    # A shell or interpreter: only when it runs one absolute, non-user-writable script.
    script = next((x for x in argv[1:] if not x.startswith("-")), "")
    return bool(re.match(r"/[^*?]+$", script)) and not nr.USER_WRITABLE.match(script)


def fileless_problem(e):
    """Why this condition names a program that isn't a file on disk, or ''. A parent that is a binary
    replaced by an update while running ("/usr/bin/Xvfb (deleted)") may narrow a filter, but doesn't pin it."""
    field, value = e["field"], e["value"]
    if field not in PATH_FIELDS[:4]:
        return ""
    path = value if field.endswith("executable") else nr.argv0(value)
    if not FILELESS.search(path) and not (field.endswith("command_line") and value.endswith("(deleted)")):
        return ""
    if field.startswith("process.parent.") and value.endswith("(deleted)") and not FILELESS.match(path):
        return ""
    return (f"{field} is not a file on disk ({path[:80]}): fileless or deleted programs (memfd, /proc, /dev, "
            f"'(deleted)') can be anything; never filter them, and filter an updated program by its real path")


def destination(value):
    """The first network destination in a command line, or None."""
    try:
        words = shlex.split(value)
    except ValueError:
        words = value.split()
    for word in words[1:]:
        for w in dict.fromkeys([word, word.split("=", 1)[-1]]):  # --server=c2.example.com
            if not w or w.startswith(("/", "-", "+", ".", "~")):
                continue
            if re.fullmatch(r"[\d:]+", w) and "::" not in w:
                continue  # a time or a ratio (12:30:00), not an IPv6 address
            hit = next((r for r in DESTINATIONS if r.match(w)), None)
            if hit is DESTINATIONS[-1] and w.rstrip(".").rsplit(".", 1)[-1].lower() in FILE_TYPES:
                continue  # job.sh, app.conf
            if hit:
                return w
    return None


def strict_problems(entries, descendants):
    why = []
    for e in entries:
        w = wildcard_problem(e["field"], e["value"])
        if w:
            why.append(w)
        if e["field"] in ("process.command_line", "process.parent.command_line"):
            d = destination(e["value"])
            if d:
                why.append(f"{e['field']} names a network destination ({d[:80]}): beacons and healthchecks are "
                           f"fixed at the source (fix_at_source), never filtered")
            pid = nr.pid_argument(e["value"])
            if pid:
                why.append(f"{e['field']} has a process ID ({pid}): it changes on every restart, so the filter "
                           f"stops matching or matches whatever gets that ID next")
        if e["field"] in ("file.path", "file.name", "dll.path") and (PERSISTENCE.search(e["value"])
                                                                      or EVIDENCE_RE.match(e["value"])):
            why.append(f"{e['field']}: a persistence, credential or log location is never filtered")
        fileless = fileless_problem(e)
        if fileless:
            why.append(fileless)
    cats = [e for e in entries if e["field"] == "event.category"]
    if cats and cats[0]["value"] not in CATEGORIES:
        why.append(f"event.category must be one of {', '.join(CATEGORIES)}")
    if descendants:
        own = [e for e in entries if e["field"] in ("process.executable", "process.command_line")]
        if not any(specific(e, True) for e in own):
            why.append("a descendants filter needs the parent's exact executable or command line, and not a "
                       "shell, supervisor, terminal or everyday tool (whatever its arguments)")
    elif not any(specific(e) for e in entries if e["field"] in ("process.executable", "process.command_line")):
        if any(specific(e) for e in entries):
            why.append("only the parent is pinned, which hides whatever it starts, now or later: pin the process "
                       "itself with its full executable path or command line")
        else:
            why.append("no condition pins it to one specific program: use a full executable path or command line "
                       "(not a bare name, not a shell, supervisor, interpreter or everyday tool)")
    else:
        # A specific parent alone is not enough when the process itself is a shell or everyday tool:
        # it would hide whatever that shell runs. It needs its own exact command line (an absolute script).
        risky = nr.SHELLS | nr.SUPERVISORS | nr.ATTACKER_TOOLS | nr.COMMON_TOOLS | nr.INTERPRETERS | nr.LOLBINS
        own = [nr.basename(e["value"]).lower() for e in entries if e["field"] == "process.executable"]
        if (own and own[0] in risky and own[0] not in nr.OWN_EVENTS_OK
                and not any(e["field"] == "process.command_line" and specific(e) for e in entries)):
            why.append(f"the process itself is {own[0]} (a shell, interpreter, everyday tool or living-off-the-land "
                       f"binary): pin its exact command line; a parent condition alone hides whatever it runs")
    # ptrace, memfd_create and the like are how code is injected or run from memory: hide them only for one
    # fixed program under one fixed parent, like a browser's crash handler watching its own browser.
    tamper = [e["value"] for e in entries
              if e["field"] == "event.action" and e["value"].lower() in nr.PINNED_ACTIONS]
    if tamper:
        own = any(specific(e) for e in entries if e["field"] in ("process.executable", "process.command_line"))
        parent = any(specific(e) for e in entries
                     if e["field"] in ("process.parent.executable", "process.parent.command_line"))
        if descendants or not own or not parent:
            why.append(f"event.action={tamper[0]} can hide code injection: it needs the program's full path or "
                       f"command line and its parent's (process.parent.executable), and no descendants")
        else:
            why += internet_facing_problems(entries, tamper[0].lower())
    return why


def internet_facing_problems(entries, action):
    """prompts/rules.md "Internet-facing programs": a browser, mail, chat or office app is where exploits land,
    so its pinned actions are hidden only in its own helpers, and a memfd only if it can't be executed."""
    val = {e["field"]: e["value"] for e in entries}
    name = lambda f: (nr.basename(val[f + ".executable"]) if f + ".executable" in val  # noqa: E731
                      else nr.program(val[f + ".command_line"])[0] if f + ".command_line" in val else "").lower()
    own, parent = name("process"), name("process.parent")
    if own not in nr.INTERNET_FACING and parent not in nr.INTERNET_FACING:
        return []
    app = own if own in nr.INTERNET_FACING else parent
    exe, par = val.get("process.executable"), val.get("process.parent.executable")
    if action == "memfd_create":
        mname = val.get("process.Ext.memfd.name", "")
        if (not exe or par != exe or not mname or "*" in mname or "?" in mname
                or val.get("process.Ext.memfd.flag_noexec_seal") != "true"):
            return [f"memfd_create in {app} (internet-facing): only in the app's own helpers, so "
                    f"process.parent.executable must equal process.executable, with process.Ext.memfd.name pinned to "
                    f"its exact name and process.Ext.memfd.flag_noexec_seal=true, so an executable memfd stays visible"]
        return []
    folder = lambda p: p.replace("\\", "/").rsplit("/", 1)[0] if p else None  # noqa: E731
    if own in nr.INTERNET_FACING or not exe or not par or folder(exe) != folder(par):
        return [f"event.action={action} in {app} (internet-facing): only the app's own helper in the app's folder "
                f"(like its crash handler), never the app itself"]
    return []


def query(f, since):
    q = {"bool": {"filter": [{"range": {"@timestamp": {"gte": f"now-{since}"}}},
                             {"term": {"host.os.type": f["os"]}}]}}
    for e in to_entries(f):
        if f.get("descendants"):
            if not e["field"].startswith("process.") or e["field"].startswith("process.parent."):
                raise ValueError("descendants filters take process.* conditions (not process.parent.*) only")
            e = dict(e, field="process.parent." + e["field"][8:])
        q["bool"]["filter"].append(nr.es_condition(e))
    return q


def evidence_query():
    """Elasticsearch: events on an EVIDENCE file, by file.path or a rename's original path."""
    return {"bool": {"minimum_should_match": 1, "should": [
        {"wildcard": {fld: {"value": g.replace("\\", "\\\\"), "case_insensitive": True}}}
        for fld in EVIDENCE_FIELDS for g in EVIDENCE]}}


def count_events(search, f, since):
    """(events over `since`, hosts, events per hour, program names, evidence). For descendants: direct
    children only. evidence: (events on EVIDENCE files, up to 5 of those paths); every such event counts."""
    res = search.search({"size": 0, "track_total_hits": True, "query": query(f, since),
                         "aggs": {"h": {"terms": {"field": "host.name", "size": 5}},
                                  "t": {"date_histogram": {"field": "@timestamp", "fixed_interval": "1h"}},
                                  "p": {"terms": {"field": "process.name", "size": 100}},
                                  "ev": {"filter": evidence_query(),
                                         "aggs": {k: {"terms": {"field": k, "size": 5}} for k in EVIDENCE_FIELDS}}}})
    aggs = res["aggregations"]
    hourly = [b["doc_count"] for b in aggs["t"]["buckets"] if b["doc_count"]]
    names = [b["key"] for b in aggs.get("p", {}).get("buckets", [])]
    ev = aggs.get("ev", {})
    paths = [b["key"] for k in EVIDENCE_FIELDS for b in ev.get(k, {}).get("buckets", []) if EVIDENCE_RE.match(b["key"])]
    return (res["hits"]["total"]["value"], [b["key"] for b in aggs["h"]["buckets"]], hourly, names,
            (ev.get("doc_count", 0), list(dict.fromkeys(paths))[:5]))


def evidence_problem(evidence):
    """Why hiding these file events would hide persistence, credential access or log wiping, or None."""
    n, paths = evidence
    if not n:
        return None
    return (f"it would hide {n:,} file event(s) on persistence, credential or log files "
            f"({', '.join(paths) or 'see file.Ext.original.path'}): never filtered; if the program's "
            f"other file events are noise, add a file.path condition for just those files")


def children_problem(names):
    """Why a descendants filter's parent is too risky to hide everything under, or None. Only what it
    starts now is known: one that starts a shell or attacker tool could start anything."""
    risky = [n for n in names if nr.basename(n).lower() in nr.SHELLS | nr.INTERPRETERS | nr.ATTACKER_TOOLS
             or nr.generic(nr.basename(n))]
    if risky:
        return (f"it starts {', '.join(sorted(set(risky))[:5])} (a shell, interpreter or attacker tool): hiding "
                f"everything it starts would hide what those run; filter the exact commands instead")
    return None


def burst_problem(n, hourly, since):
    """Why these events look like a burst rather than steady noise, or None."""
    if not n or not hourly or (nr.window_seconds(since) or 0) < 12 * 3600:
        return None
    if max(hourly) > BURST_SHARE * n:
        return (f"a burst, not steady noise: {max(hourly):,} of its {n:,} events came in one hour; "
                f"find the cause (fix_at_source), don't filter it")
    if len(hourly) < MIN_HOURS:
        return (f"a burst, not steady noise: all {n:,} events came in {len(hourly)} hour(s) of {since}; "
                f"find the cause (fix_at_source), don't filter it")
    return None


def total_events(search, since):
    res = search.search({"size": 0, "track_total_hits": True,
                         "query": {"range": {"@timestamp": {"gte": f"now-{since}"}}}})
    return res["hits"]["total"]["value"]


def gate(search, f, total, since, max_share):
    """Reasons the filter fails the code checks ([] = passes), events it matches, hosts."""
    try:
        entries = to_entries(f)
    except ValueError as e:
        return [str(e)], 0, []
    why = []
    desc = bool(f.get("descendants"))
    if not desc and not any(e["field"] == "event.category" for e in entries):
        why.append("needs an event.category condition (otherwise it hides every kind of event)")
    r = nr.conditions_risk(entries, desc)
    if r:
        why.append(r)
    why += strict_problems(entries, desc)
    for e in entries:
        if e["field"] in PATH_FIELDS:
            try:
                words = [e["value"]] if e["field"].endswith("executable") else shlex.split(e["value"])
            except ValueError:
                words = e["value"].split()
            # Any path in it counts, not just argv[0]: in "sh -c /home/x/job.sh" the job is what runs.
            bad = [w for w in words if nr.USER_WRITABLE.match(w.lstrip("<>|&;(").split("=", 1)[-1])]
            if bad:
                why.append(f"{e['field']} runs from a user-writable path ({bad[0]}); easy to impersonate")
            rel = (e["value"] if not re.match(r"(/|[A-Za-z]:\\)", e["value"]) else None) \
                if not e["field"].endswith("command_line") else nr.relative_path(e["value"])
            if rel:
                why.append(f"{e['field']} has a relative path ({rel[:80]}); the same command from any folder "
                           f"would match")
    if why:
        return why, 0, []
    try:
        n, hosts, hourly, names, evidence = count_events(search, f, since)
    except ValueError as e:
        return why + [str(e)], 0, []
    except SystemExit as e:  # an Elasticsearch error: the filter is refused, the step goes on
        return why + [f"could not count it: {str(e)[:200]}"], 0, []
    if n == 0:
        why.append(f"matches no events over {since}")
    elif total and n > max_share * total:
        why.append(f"would hide {n / total:.0%} of all events (limit {max_share:.0%})")
    burst = burst_problem(n, hourly, since)
    if burst:
        why.append(burst)
    ev = evidence_problem(evidence)
    if ev:
        why.append(ev)
    if desc:
        kids = children_problem(names)
        if kids:
            why.append(kids)
    return why, n, hosts
