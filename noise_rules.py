"""The filter rules as code, shared by every mode: which programs and paths are too broad or
unsafe to filter (safety.json), how a row becomes filter conditions, and how conditions become
Elasticsearch queries. Pure functions: no network, no credentials, nothing that changes Elastic.
"""
import json
import os
import re
import shlex
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# Programs and paths not to build broad filters on: safety.json beside this script, overridden
# key by key by the files after it. load_safety() fills these in.
SAFETY_FILES = [os.path.join(HERE, "safety.json"),
                os.path.join(HERE, "safety.local.json")]
SHELLS = ATTACKER_TOOLS = COMMON_TOOLS = INTERPRETERS = SUPERVISORS = OWN_EVENTS_OK = LOLBINS = PINNED_ACTIONS = frozenset()
INTERNET_FACING = frozenset()
USER_WRITABLE = re.compile(r"(?!)")


def load_safety(allow=()):
    global SHELLS, ATTACKER_TOOLS, COMMON_TOOLS, INTERPRETERS, SUPERVISORS, OWN_EVENTS_OK, LOLBINS, USER_WRITABLE
    global PINNED_ACTIONS, INTERNET_FACING
    cfg = {}
    for path in SAFETY_FILES:
        if os.path.exists(path):
            try:
                with open(path) as f:
                    cfg.update(json.load(f))
            except (OSError, ValueError) as e:
                sys.exit(f"Can't read {path}: {e}")
    if not cfg:
        sys.exit(f"No safety list found; expected {SAFETY_FILES[0]}.")
    allowed = {x.lower() for x in list(cfg.get("allow", [])) + list(allow)}

    def names(key):
        return frozenset(x.lower() for x in cfg.get(key, [])) - allowed

    SHELLS, ATTACKER_TOOLS, COMMON_TOOLS = names("shells"), names("attacker_tools"), names("common_tools")
    INTERPRETERS, SUPERVISORS = names("interpreters"), names("supervisors")
    LOLBINS = names("lolbins")  # LOLBAS/GTFOBins/LOOBins: only by exact command line
    OWN_EVENTS_OK = frozenset(x.lower() for x in cfg.get("supervisors_own_events_ok", []))
    PINNED_ACTIONS = frozenset(x.lower() for x in cfg.get("pinned_actions", []))  # not affected by allow
    INTERNET_FACING = frozenset(x.lower() for x in cfg.get("internet_facing", []))  # nor this
    prefixes = [x for x in cfg.get("user_writable_paths", []) if x.lower() not in allowed]
    # A Windows prefix such as C:\\Users\\ matches on any drive letter.
    pats = ["[A-Za-z]:" + re.escape(x[2:]) if re.match(r"[A-Za-z]:\\", x) else re.escape(x) for x in prefixes]
    USER_WRITABLE = (re.compile("^(" + "|".join(pats) + ")", re.I) if prefixes
                     else re.compile(r"(?!)"))


def read_key_file(path):
    """The ELASTIC_API_KEY in a key file (read.env, write.env)."""
    key = read_env_file(path).get("ELASTIC_API_KEY", "")
    if not key or " " in key:
        sys.exit(f"{path} needs one line: ELASTIC_API_KEY=<the key>")
    return key


def read_env_file(path):
    values = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            values[k.strip().removeprefix("export ")] = v.strip().strip("'\"")
    return values


def basename(path):
    return path.replace("\\", "/").rsplit("/", 1)[-1]


def program(cmdline):
    try:
        argv = shlex.split(cmdline)
    except ValueError:
        argv = cmdline.split()
    # Some daemons retitle themselves, e.g. "sshd: /usr/sbin/sshd -D [listener]".
    return (basename(argv[0]).rstrip(":") if argv else ""), argv[1:]


def generic(name):
    name = name.lower()
    return (name in SHELLS or name in SUPERVISORS or name in INTERPRETERS
            or any(name.startswith(p) and name[len(p):].replace(".", "").isdigit() for p in INTERPRETERS))


def risk(kind, value):
    """Return why a global filter on this value is too broad, or ''."""
    if kind == "exe":
        name = basename(value)
        return (f"every {name} on the OS"
                if generic(name) or name.lower() in ATTACKER_TOOLS or name.lower() in COMMON_TOOLS
                or name.lower() in LOLBINS else "")
    name, args = program(value)
    real_args = [x for x in args if not x.startswith("-")]
    if kind == "cmd":
        if name.lower() in SUPERVISORS and name.lower() not in OWN_EVENTS_OK:
            return f"{name}'s own events (e.g. every new session it forks)"
        return f"any bare '{value}'" if generic(name) and not real_args else ""
    # children: anything started by a supervisor or bare shell is far too much
    if name.lower() in SUPERVISORS or (generic(name) and not real_args):
        return f"everything started by {name}"
    return ""


UUID = re.compile(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}")
# A directory (not the final file name) that holds a version or build number: /1.2.3.4/,
# /snap/brave/690/, /iOS 27.0.simruntime/. These change on every update.
# In a command line a space ends the path; in an executable path it doesn't.
VERSIONED_DIR = re.compile(r"(?<=/)(?:[^/\s]*\d+\.\d+[^/\s]*|\d+)(?=/)")
VERSIONED_DIR_IN_PATH = re.compile(r"(?<=/)(?:[^/]*\d+\.\d+[^/]*|\d+)(?=/)")


def suggest_wildcard(value, is_path=False):
    """The value with version/UUID directories replaced by *, or None if there are none."""
    out = (VERSIONED_DIR_IN_PATH if is_path else VERSIONED_DIR).sub("*", UUID.sub("*", value))
    out = re.sub(r"\*(/\*)+", "*", out)
    return out if out != value else None


def argv0(cmdline):
    try:
        argv = shlex.split(cmdline)
    except ValueError:
        argv = cmdline.split()
    return argv[0] if argv else ""


def split_args(cmdline):
    try:
        return shlex.split(cmdline)
    except ValueError:
        return cmdline.split()


# A process ID changes on every restart: the filter stops matching, or matches whatever gets that ID next.
PID_BARE = frozenset("kill vmmap heap leaks malloc_history sample gcore pmap procdump.exe procdump64.exe".split())
PID_FLAG = frozenset("lsof strace ltrace gdb lldb perf pidstat top htop taskset prlimit renice py-spy dtrace "
                     "dtruss taskpolicy".split())


def pid_argument(cmdline):
    """The process ID in a command line ("vmmap 129", "lsof -p 42", "--pid=42", /proc/42/), or None."""
    m = re.search(r"/proc/(\d+)(/|\b)", cmdline)
    if m:
        return m[0]
    argv = split_args(cmdline)
    if not argv:
        return None
    name = basename(argv[0]).lower()
    for i, a in enumerate(argv[1:], 1):
        nxt = argv[i + 1] if i + 1 < len(argv) else ""
        if re.fullmatch(r"--?pid=\d+", a) or (a in ("--pid", "-pid") and nxt.isdigit()):
            return f"{a} {nxt}".strip()
        if name in PID_FLAG and (re.fullmatch(r"-p\d+", a) or (a == "-p" and nxt.isdigit())):
            return f"{a} {nxt}".strip() if a == "-p" else a
        if name in PID_BARE and a.isdigit():
            return a
    return None


def relative_path(cmdline):
    """The first relative path in a command line, or None: ./x, ../x and ~/x anywhere, and a program or
    script named without a leading / ("tools/watch.sh"). The same command from another folder would match."""
    argv = split_args(cmdline)
    if not argv:
        return None
    for a in argv:
        for w in re.split(r"[\s;&|<>()=]+", a):
            if w.startswith(("./", "../", "~/")):
                return w
    absolute = re.compile(r"(/|[A-Za-z]:)")
    w = argv[0]
    if "/" in w and not absolute.match(w) and "://" not in w:
        return w
    name = basename(w).lower()
    if name in SHELLS or (generic(name) and name not in SUPERVISORS):
        if "-c" in argv[1:-1]:
            # sh -c "a && b": each command in the string runs
            for part in re.split(r"&&|\|\||[;|&()\n]", argv[argv.index("-c") + 1]):
                r = relative_path(part.strip())
                if r:
                    return r
        elif name in SHELLS or not {"-e", "-m", "-E"} & set(argv[1:]):  # an interpreter's code or module
            script, args = "", iter(argv[1:])
            for a in args:
                if a in ("-o", "+o", "-O", "+O"):
                    next(args, None)  # bash -o pipefail
                elif not a.startswith(("-", "+")):
                    script = a
                    break
            if script and not absolute.match(script):
                return script  # the script a shell or interpreter runs
    return None


def skip_reason(kind, value, executable):
    r = risk(kind, value)
    if r:
        return f"too broad: {r}"
    if kind == "exe" and not (value.startswith("/") or re.match(r"[A-Za-z]:\\", value)):
        return f"not a full path ({value!r})"
    if kind != "exe":
        name, args = program(value)
        if (name.lower() in COMMON_TOOLS or name.lower() in ATTACKER_TOOLS) and not argv0(value).startswith("/"):
            return f"everyday tool by bare name ('{value}'); too generic to match on"
        if name.lower() in LOLBINS and any(c in value for c in "*?"):
            return f"{name} is a living-off-the-land binary: only its exact command line, no wildcards"
        rel = relative_path(value)
        if rel:
            return f"relative path ({rel}); the same command from any folder would match"
        pid = pid_argument(value)
        if pid:
            return f"process ID ({pid}); it changes on every restart"
    path = value if kind == "exe" else (executable or argv0(value))
    if USER_WRITABLE.match(path):
        return f"runs from a user-writable dir ({path}); easy to impersonate"
    return ""


def make_entries(kind, category, value, action=None):
    """The filter conditions for a row, with version/UUID directories already wildcarded."""
    wildcard = suggest_wildcard(value, is_path=kind == "exe")
    entries = [{"field": "process.executable" if kind == "exe" else "process.command_line",
                "operator": "included", "type": "wildcard" if wildcard else "match", "value": wildcard or value}]
    if kind != "children":
        entries.append({"field": "event.category", "operator": "included", "type": "match", "value": category})
    if action:
        entries.append({"field": "event.action", "operator": "included", "type": "match", "value": action})
    return entries


def window_seconds(since):
    m = re.fullmatch(r"(\d+)([smhdw])", since)
    return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[m.group(2)] if m else None


# Fields that pin a filter to specific activity. A filter needs at least one of these with a
# specific value, otherwise it hides a whole category of events. Ports are not here: every
# client of a service shares its port, so "curl to port 80" is still every plain-HTTP curl.
NARROWING = ("process.executable", "process.name", "process.command_line", "process.parent.executable",
             "process.parent.name", "process.parent.command_line", "file.path", "file.name",
             "dll.path", "dns.question.name", "destination.ip",
             "process.code_signature.subject_name")


def conditions_risk(entries, descendants):
    """Why this filter would hide too much, or ''."""
    narrow = []
    for e in entries:
        if e["field"] not in NARROWING:
            continue
        v = e["value"]
        if e["type"] == "wildcard":
            literal = re.sub(r"[*?]", "", v)
            last = v.replace("\\", "/").rsplit("/", 1)[-1]
            if len(literal) < 8 or v.startswith(("*", "?")) or ("path" in e["field"] or
                                                               e["field"].endswith("executable")) and \
                    any(ch in last for ch in "*?"):
                continue  # too loose to count as narrowing
            v = literal
        values = v if isinstance(v, list) else [v]  # match_any ("is one of") has a list
        if e["field"].startswith("process.parent."):
            # "Started by this exact parent" narrows well, unless the parent is just a bare shell.
            if values and not any(generic(program(x)[0]) and not [y for y in program(x)[1] if not y.startswith("-")]
                                  for x in values):
                narrow.append(e)
            continue
        kind = "children" if descendants else ("exe" if e["field"].endswith(("executable", ".name")) else "cmd")
        if values and not any(risk(kind, x) for x in values):
            narrow.append(e)
    if not narrow:
        what = "everything started by that" if descendants else "an entire category of events"
        return (f"no specific program/command/path among the conditions, so it would hide {what} "
                f"(or the program is a shell, supervisor or attacker-favoured tool)")
    return ""


def term_or_wildcard(field, value):
    """FIELD=VALUE for --term / explain --match: exact, or a wildcard match if VALUE has * or ?."""
    if "*" in value or "?" in value:
        return {"wildcard": {field: {"value": value}}}
    return {"term": {field: value}}


def es_condition(e):
    if e["type"] == "wildcard":
        return {"wildcard": {e["field"]: {"value": e["value"]}}}
    return {"term": {e["field"]: e["value"]}}
