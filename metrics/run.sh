#!/bin/sh
# Daily metrics: ingest, what every event filter saves, and the Elastic bill -> InfluxDB (noise-metrics.py).
# No model and only read-only keys, so it runs directly (no container or proxy, unlike agent/deploy/run.sh).
#
# In metrics/config/: metrics.env (ELASTIC_URL, INFLUXDB_*, EC_API_KEY, GRAFANA_*) and read.env
# (ELASTIC_API_KEY=<read-only key that may also list event filters>). Both are checked by the script.
# Kill switch: touch metrics/DISABLED. One run at a time. Log: metrics/runs/<UTC time>.log.
# NOISE_NOTIFY: command fed the summary line on stdin (optional). Extra arguments go to noise-metrics.py,
# e.g. `metrics/run.sh --days 7 --billing-days 90` to backfill.
set -eu
cd "$(dirname "$0")"
[ ! -e DISABLED ] || { echo "metrics/DISABLED exists: not running."; exit 0; }
for f in config/metrics.env config/read.env; do
    [ -r "$f" ] || { echo "missing metrics/$f (see metrics/config/metrics.env.example)"; exit 1; }
done
command -v flock >/dev/null || { echo "flock (util-linux) is needed."; exit 1; }
exec 9>"${XDG_RUNTIME_DIR:-/tmp}/noise-metrics.lock"
flock -n 9 || { echo "Another metrics run is going: not running."; exit 1; }
mkdir -p runs
LOG="runs/$(date -u +%Y%m%dT%H%M%SZ).log"
rc=0
python3 noise-metrics.py "$@" >"$LOG" 2>&1 || rc=$?
summary=$(grep '^metrics:' "$LOG" | paste -sd' ' -)   # the savings line, then what was written
[ -n "$summary" ] || summary="metrics failed (exit $rc): $(grep -v '^\s*$' "$LOG" | tail -1)"
echo "$summary"
[ -z "${NOISE_NOTIFY:-}" ] || printf '%s\n' "$summary" | $NOISE_NOTIFY || true
exit "$rc"
