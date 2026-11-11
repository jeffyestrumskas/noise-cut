#!/bin/sh
# rows -> propose -> validate -> apply, each in a fresh container that gets only its own code
# (a copy in run-<time>/code/<step>), its own keys (a temporary settings file) and its own
# network destinations (the proxy's allowlist is rebuilt for every step):
#
#   step           code                          Elastic key   reaches
#   rows           noise-pipeline, noise-cut read.env        Elasticsearch, Kibana (read)
#   propose        noise-agent + read-only tools read.env        Elasticsearch, Ollama or Venice (+ its key), sanitizer
#   validate       noise-agent + read-only tools read.env        Elasticsearch, Ollama or Venice (+ its key), sanitizer
#   apply-dry-run  noise-pipeline (no writer)    read.env        Elasticsearch
#   apply          noise-pipeline, noise-cut write.env       Elasticsearch, Kibana
#
# In agent/config/: agent.env (ELASTIC_URL, Ollama or Venice, models, limits; no Elastic key),
# read.env (ELASTIC_API_KEY=<read-only key>), write.env (ELASTIC_API_KEY=<event filter key>; only for NOISE_DRY_RUN=0).
#
# Filters are created only with NOISE_DRY_RUN=0; anything else (or unset) is a dry run.
# Kill switch: touch DISABLED in agent/ or in the run's data folder; checked before every step,
# and by the steps before every row, filter and filter creation.
# Only data/ is writable by the steps; code/ and acl/ beside it are not mounted writable anywhere.
# NOISE_NOTIFY: command fed summary.txt on stdin (optional).
set -eu
cd "$(dirname "$0")"
AGENT=$(cd .. && pwd)
REPO=$(cd ../.. && pwd)
CONF=$AGENT/config
AGENT_ENV="${NOISE_AGENT_ENV:-$CONF/agent.env}"   # ELASTIC_URL, Ollama or Venice, models, limits
READ_KEY="${NOISE_READ_KEY:-$CONF/read.env}"      # ELASTIC_API_KEY=<read-only key>
WRITE_KEY="${NOISE_WRITE_KEY:-$CONF/write.env}"   # ELASTIC_API_KEY=<event filter key>; only for NOISE_DRY_RUN=0
DRY=1; [ "${NOISE_DRY_RUN:-1}" = 0 ] && DRY=0
export NOISE_UID="$(id -u)" NOISE_GID="$(id -g)"
RUN="${NOISE_OUT:-$AGENT/runs}/run-$(date -u +%Y%m%dT%H%M%SZ)"
export NOISE_RUN="$RUN/data"   # mounted as /out: the only folder a step can write
NOISE_STATE="${NOISE_CUT_STATE:-${ELASTIC_NOISE_STATE:-$HOME/.local/share/noise-cut}}"
[ -n "${NOISE_CUT_STATE:-}${ELASTIC_NOISE_STATE:-}" ] || [ -d "$NOISE_STATE" ] || [ ! -d "$HOME/.local/share/elastic-noise" ] ||
    NOISE_STATE="$HOME/.local/share/elastic-noise"   # state from before the rename
export NOISE_STATE
export NOISE_CODE=/nonexistent NOISE_SECRET=/nonexistent NOISE_ACL=/nonexistent

[ ! -e "$AGENT/DISABLED" ] || { echo "DISABLED exists: not running."; exit 0; }
# Check everything first and report every problem at once.
val() { sed -n "s/^\(export \)\{0,1\}$1=//p" "$2" 2>/dev/null | tail -1 | tr -d "\"' "; }
err=""
if [ ! -r "$AGENT_ENV" ]; then
    err="$err\n  missing $AGENT_ENV (copy agent/config/agent.env.example)"
else
    for v in ELASTIC_URL NOISE_PROPOSER NOISE_VALIDATOR; do
        [ -n "$(val $v "$AGENT_ENV")" ] || err="$err\n  set $v in $AGENT_ENV"
    done
    [ -z "$(val ELASTIC_API_KEY "$AGENT_ENV")" ] ||
        err="$err\n  $AGENT_ENV has an ELASTIC_API_KEY: move that line into $READ_KEY"
    p=$(val NOISE_PROPOSER "$AGENT_ENV"); o=$(val OLLAMA_HOST "$AGENT_ENV"); o=${o:-https://ollama.com}
    [ -z "$p" ] || [ "$p" != "$(val NOISE_VALIDATOR "$AGENT_ENV")" ] || err="$err\n  NOISE_VALIDATOR must differ from NOISE_PROPOSER"
    case "$(val NOISE_PROVIDER "$AGENT_ENV")" in
        venice) [ -n "$(val VENICE_API_KEY "$AGENT_ENV")" ] || err="$err\n  set VENICE_API_KEY in $AGENT_ENV (needed for NOISE_PROVIDER=venice)" ;;
        ""|ollama)
            case "$o" in *ollama.com*) [ -n "$(val OLLAMA_API_KEY "$AGENT_ENV")" ] || err="$err\n  set OLLAMA_API_KEY in $AGENT_ENV (needed for ollama.com)";; esac
            case "$o" in https://*|http://*) ;; *) err="$err\n  OLLAMA_HOST must start with https:// or http://";; esac ;;
        *) err="$err\n  NOISE_PROVIDER must be ollama or venice" ;;
    esac
    s=$(val NOISE_SANITIZER_URL "$AGENT_ENV")
    case "$s" in ""|https://*|http://*) ;; *) err="$err\n  NOISE_SANITIZER_URL must start with https:// or http://";; esac
    case "$s" in *ollama.com*) err="$err\n  NOISE_SANITIZER_URL must be a local Ollama, not ollama.com";; esac
    [ -z "$s" ] || [ -n "$(val NOISE_SANITIZER_MODEL "$AGENT_ENV")" ] || err="$err\n  set NOISE_SANITIZER_MODEL in $AGENT_ENV"
fi
key() { val ELASTIC_API_KEY "$1"; }   # the key in read.env / write.env
[ -n "$(key "$READ_KEY")" ] || err="$err\n  missing $READ_KEY with ELASTIC_API_KEY=<the read-only key>"
if [ "$DRY" = 0 ]; then
    [ -n "$(key "$WRITE_KEY")" ] || err="$err\n  missing $WRITE_KEY with ELASTIC_API_KEY=<the event filter key> (needed with NOISE_DRY_RUN=0)"
    [ "$(key "$WRITE_KEY")" != "$(key "$READ_KEY")" ] || err="$err\n  read.env and write.env hold the same key"
fi
[ -z "$err" ] || { printf "Not running:$err\n"; exit 1; }
# One run at a time: runs share the docker network and proxy.
LOCK="${XDG_RUNTIME_DIR:-/tmp}/noise-agent.lock"
command -v flock >/dev/null || { echo "flock (util-linux) is needed."; exit 1; }
exec 9>"$LOCK"
flock -n 9 || { echo "Another noise-agent run is going (lock $LOCK): not running."; exit 1; }
# Holding the lock, so anything named noise-agent-* is left over from a run that was killed.
old=$(docker ps -aq --filter name=noise-agent-); [ -z "$old" ] || docker rm -f $old >/dev/null
old=$(docker network ls -q --filter name=noise-agent-); [ -z "$old" ] || docker network rm $old >/dev/null
mkdir -p "$RUN" "$NOISE_RUN" "$NOISE_STATE"
PROJECT="noise-agent-$(date -u +%Y%m%d%H%M%S)"
[ "$DRY" = 1 ] && echo "Dry run: nothing will be created (NOISE_DRY_RUN=0 to create filters)."

# Keys live only in this temporary folder, one file per step, removed on exit.
SECRETS=$(umask 077 && mktemp -d "${XDG_RUNTIME_DIR:-/tmp}/noise-agent.XXXXXX")
pick() {   # pick FILE KEY... : those settings only
    f=$1; shift
    for k in "$@"; do v=$(sed -n "s/^\(export \)\{0,1\}$k=//p" "$f" | tail -1); [ -z "$v" ] || printf '%s=%s\n' "$k" "$v"; done
}
LIMITS="NOISE_MAX_FILTERS NOISE_MAX_SHARE NOISE_MAX_TOKENS"
PRIVACY="NOISE_INTERNAL_DOMAINS NOISE_INTERNAL_HOSTNAMES NOISE_SANITIZER_URL NOISE_SANITIZER_MODEL"   # for the model steps' pseudonyms
(umask 077
 { pick "$AGENT_ENV" ELASTIC_URL KIBANA_URL; echo "ELASTIC_API_KEY=$(key "$READ_KEY")"; } > "$SECRETS/rows.env"
 { pick "$AGENT_ENV" ELASTIC_URL NOISE_PROVIDER OLLAMA_HOST OLLAMA_API_KEY VENICE_API_KEY NOISE_PROPOSER NOISE_VALIDATOR $LIMITS $PRIVACY
   echo "ELASTIC_API_KEY=$(key "$READ_KEY")"; } > "$SECRETS/model.env"
 if [ "$DRY" = 1 ]; then
     { pick "$AGENT_ENV" ELASTIC_URL $LIMITS; echo "ELASTIC_API_KEY=$(key "$READ_KEY")"; } > "$SECRETS/apply-dry-run.env"
 else
     { pick "$AGENT_ENV" ELASTIC_URL KIBANA_URL $LIMITS; echo "ELASTIC_API_KEY=$(key "$WRITE_KEY")"; } > "$SECRETS/apply.env"
 fi)

# Each step's code: only the files it runs, laid out as in the repo. Kept in the run folder, with
# hashes, as a record.
SHARED="noise_rules.py es_read.py safety.json agent/noise_gate.py"
code() {   # code STEP FILE... (paths from the repo root)
    d="$RUN/code/$1"; shift; mkdir -p "$d/agent"
    for f in $SHARED "$@"; do cp -r "$REPO/$f" "$d/$f"; done
    [ ! -f "$REPO/safety.local.json" ] || cp "$REPO/safety.local.json" "$d/"
    (cd "$d" && find . -type f ! -name SHA256SUMS | sort | xargs sha256sum > SHA256SUMS)
}
code rows agent/noise-pipeline.py noise-cut.py
code propose agent/noise-agent.py agent/agent_tools.py agent/pseudo.py agent/sanitizer.py agent/prompts explain.py
ln -s propose "$RUN/code/validate"
if [ "$DRY" = 1 ]; then code apply-dry-run agent/noise-pipeline.py; else code apply agent/noise-pipeline.py noise-cut.py; fi

# Where each step may connect (squid allowlists, from the settings files).
host() { printf '%s\n' "$1" | sed -E 's#^[a-zA-Z]+://##; s#[/:?].*$##'; }
es=$(host "$(val ELASTIC_URL "$AGENT_ENV")")
kb=$(val KIBANA_URL "$AGENT_ENV"); kb=$(host "${kb:-$(val ELASTIC_URL "$AGENT_ENV" | sed 's/\.es\./.kb./')}")
ol=$(val OLLAMA_HOST "$AGENT_ENV"); ol=${ol:-https://ollama.com}
[ "$(val NOISE_PROVIDER "$AGENT_ENV")" != venice ] || ol=api.venice.ai   # as VENICE_URL in noise-agent.py
acl() {   # acl STEP HOST... ; local http:// Ollamas are the only plain-HTTP destinations
    d="$RUN/acl/$1"; shift; mkdir -p "$d"
    echo none.invalid > "$d/http-hosts"; echo 1 > "$d/http-port"
    : > "$d/https-hosts.tmp"
    for h in "$@"; do
        case "$h" in
            http://*) host "$h" >> "$d/http-hosts"
                      p=$(printf '%s\n' "$h" | sed -nE 's#^http://[^/:]+:([0-9]+).*#\1#p'); echo "${p:-80}" >> "$d/http-port" ;;
            https://*) host "$h" >> "$d/https-hosts.tmp" ;;
            *) echo "$h" >> "$d/https-hosts.tmp" ;;
        esac
    done
    sort -u "$d/https-hosts.tmp" > "$d/https-hosts"; rm -f "$d/https-hosts.tmp"
}
acl rows "$es" "$kb"
san=$(val NOISE_SANITIZER_URL "$AGENT_ENV")
acl propose "$es" "$ol" ${san:+"$san"}
ln -s propose "$RUN/acl/validate"
if [ "$DRY" = 1 ]; then acl apply-dry-run "$es"; else acl apply "$es" "$kb"; fi

dc() { docker compose -p "$PROJECT" "$@"; }
proxy_log() { timeout 30 docker compose -p "$PROJECT" exec -T proxy cat /var/log/squid/noise-access.log </dev/null >>"$RUN/proxy-access.log" 2>/dev/null || true; }
cleanup() { proxy_log; dc logs --no-color proxy >"$RUN/proxy.log" 2>&1 || true
            dc down -t 5 --remove-orphans >/dev/null 2>&1 || true; rm -rf "$SECRETS"; }
trap cleanup EXIT
trap 'exit 130' INT TERM HUP   # dash skips the EXIT trap when killed by a signal

[ "$DRY" = 1 ] && last=apply-dry-run || last=apply
for step in rows propose validate $last; do
    for k in "$AGENT/DISABLED" "$NOISE_RUN/DISABLED"; do
        [ ! -e "$k" ] || { echo "$k exists: stopping before $step." | tee "$NOISE_RUN/summary.txt"; exit 0; }
    done
    case "$step" in propose|validate) secret=model.env ;; *) secret=$step.env ;; esac
    export NOISE_CODE="$RUN/code/$step" NOISE_SECRET="$SECRETS/$secret" NOISE_ACL="$RUN/acl/$step"
    proxy_log
    echo "   starting the proxy for $step"
    timeout 120 docker compose -p "$PROJECT" up -d --force-recreate proxy </dev/null >"$RUN/proxy-start.log" 2>&1 ||
        { echo "proxy did not start for $step, see $RUN/proxy-start.log" | tee "$NOISE_RUN/summary.txt"; cat "$RUN/proxy-start.log"; exit 1; }
    sleep 3
    [ -n "$(dc ps -q --status running proxy)" ] || { echo "proxy did not start, see $RUN/proxy.log" | tee "$NOISE_RUN/summary.txt"; exit 1; }
    echo "== $step  $(date -u +%H:%M:%S)  (log: $RUN/$step.log)"
    # Backstop only: noise-agent.py limits each row/filter (--max-seconds, --max-steps) and the step's tokens.
    case "$step" in propose|validate) limit=14400 ;; *) limit=1800 ;; esac
    # Shown live and saved; the exit code goes through a file because of the pipe.
    { timeout "$limit" docker compose -p "$PROJECT" run --rm -T "$step" </dev/null 2>&1; echo $? >"$RUN/.rc"; } | tee "$RUN/$step.log"
    [ "$(cat "$RUN/.rc")" = 0 ] || { printf '%s failed: %s\n(full log: %s)\n' "$step" "$(grep -v '^\s*$' "$RUN/$step.log" | tail -1)" "$RUN/$step.log" | tee "$NOISE_RUN/summary.txt"; break; }
done
[ -f "$NOISE_RUN/summary.txt" ] || echo "no summary (see the step logs in $RUN)" > "$NOISE_RUN/summary.txt"
cp "$NOISE_RUN/summary.txt" "$RUN/summary.txt"
cat "$RUN/summary.txt"
[ -z "${NOISE_NOTIFY:-}" ] || $NOISE_NOTIFY < "$RUN/summary.txt" || true
