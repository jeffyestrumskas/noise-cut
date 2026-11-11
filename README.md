# Noise Cut

Noise Cut is an experimental log tuning agent that cuts Elastic log noise to reduce ingest and storage costs. Trust is split across Elastic Cloud (trusted as a risk tradeoff, stores the logs), a SaaS inference provider (not trusted, runs the models for **Propose** and **Validate**) and a local model (trusted, **Sanitize**, aids in sanitization before data goes to the inference provider).

Deterministic code aggregates the noisiest events, replaces host names, users, IPs and secrets with stand-ins before any data goes to the inference provider, re-checks the filters from **Propose**, then creates the actual filters in Elastic Cloud. The models have least privilege, with no access to API keys and only deterministic read-only tools.

### Security Model

The design assumes any model can be prompt injected by text in the logs. So the controls are deterministic, and limit the tools, data and network access each model has.

- Execution flow is fixed (**Rows**, **Propose**, **Validate**, **Apply**), with no ability for a model to modify it.
- Models get three tools that ask our code for counts and top values on fixed fields. Arguments are checked against a schema, and no raw events come back.
- The model steps don't have the code or the key to create filters. Their key is checked to be read-only before it's used.
- Each step runs in its own Docker container with its own key, and all egress goes through the squid proxy. The model steps can't reach Kibana and **Apply** can't reach the inference provider.

| Step | Data | Tools | Network |
|---|---|---|---|
| **Propose** (`kimi-k3`) | one of the top 20 aggregates from `noise-cut.py`, as stand-ins | `breakdown`, `count`, `explain`, `submit` | none |
| **Validate** (`deepseek-v4.1-flash:1017`) | one proposed filter, with its event count and hosts, as stand-ins | `breakdown`, `count`, `explain`, `verdict` | none |
| **Sanitize** (local, optional) | each new line before it goes to the inference provider, as it is | none | none |

The inference provider never sees raw events or keys. `breakdown`, `count` and `explain` let a model look into the noise before it proposes or approves a filter: our code runs the search with the read-only key and returns counts, command lines and paths with stand-ins. `submit` and `verdict` only hand back the model's answer.

## Setup

Copy each `.example` file to the same name without it, and `chmod 600`.

| File | Holds |
|---|---|
| `config/user.env` | Human mode: `ELASTIC_URL` and the event filter key |
| `agent/config/agent.env` | Agent mode: `ELASTIC_URL`, provider (Ollama or Venice), models, local sanitizer, limits |
| `agent/config/read.env`, `write.env` | Agent mode: the read-only key and the event filter key |
| `metrics/config/metrics.env`, `read.env` | Metrics: InfluxDB, Elastic Cloud and Grafana settings, and the metrics key |

Human mode is the scripts at the top level, Agent mode is in `agent/` and Metrics in `metrics/`. All three share `noise_rules.py`, `es_read.py`, `explain.py`, `noise-cut.py` and `safety.json`.

## Human mode

```
python3 noise-cut.py                          # top 10 filters, last 24h
python3 noise-cut.py --ignore-rule 3,5        # preview, confirm, create
python3 noise-cut.py --count ... --since 15m  # check a filter works
python3 explain.py --host H --match FIELD=VALUE   # look into one stream
```

Read `agent/prompts/rules.md` before creating filters. Rows that would hide too much are listed under "Not proposed", using the lists in `safety.json`.

## Agent mode

```
rows      code         finds the noisiest events                  -> rows.json
sanitize  local model  names identifying values in each new line
pseudo    code         swaps those, and every known name, for stand-ins
propose   model 1      suggests filters, one row at a time        -> proposals.json
validate  model 2      approves or rejects each filter            -> verdicts.json
apply     code         reruns the code checks and creates
                       what passed (dry run by default)           -> summary.txt
```

Setup (Python 3, Docker with compose, flock):

- Create the keys (API Keys below): the read-only key in `agent/config/read.env`, and the event filter key in `agent/config/write.env` (only needed to create filters), each as `ELASTIC_API_KEY=<key>`.
- `cp agent/config/agent.env.example agent/config/agent.env`, then set `ELASTIC_URL`, the provider and its key, and the models. `chmod 600 agent/config/*.env`.
- Dry run, then read `agent/runs/<run>/summary.txt`:

```
agent/deploy/run.sh                    # dry run (default)
NOISE_DRY_RUN=0 agent/deploy/run.sh    # create filters
python3 -m unittest discover agent/tests
```

- Schedule it, e.g. cron: `0 3 * * * /path/to/agent/deploy/run.sh >>/path/to/agent/runs/cron.log 2>&1`.

**Propose** and **Validate** run on ollama.com by default. Set `NOISE_PROVIDER=venice` and `VENICE_API_KEY` in `agent.env` to use venice.ai instead, with models that support function calling. **Sanitize** always uses your own Ollama.

With `NOISE_DRY_RUN=0` no human approves each filter, so run dry runs until the results are consistently right. Created filters are marked `noise-agent:`, and `agent/noise-pipeline.py revert --since 7d` deletes them.

Everything the models are told is in `agent/prompts/`: the system prompts (`propose.md`, `validate.md`), `rules.md`, and the messages sent during a conversation (`messages.md`), and **Sanitize**'s prompt (`sanitize.md`).

### OWASP mapping

[Agentic Top 10 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) and [LLM Top 10 2025](https://genai.owasp.org/llm-top-10/).

| Risk | Controls |
|---|---|
| Goal hijack, prompt injection (ASI01, LLM01) | log text marked as data; models return only data; code and a second model decide |
| Tool misuse, excessive agency (ASI02, LLM06) | read-only tools; fixed fields; caps on calls, turns, time, tokens |
| Privilege abuse (ASI03) | separate keys, each checked against an allowlist |
| Supply chain (ASI04, LLM03) | pinned images; standard library only; hashed read-only code per step |
| Code execution (ASI05) | no shell or `eval` in model steps; non-root, read-only containers |
| Context poisoning (ASI06) | fresh context per row and filter; code re-checks every proposal |
| Inter-agent tampering (ASI07) | typed JSON; verdicts bound to the filter's fingerprint |
| Cascading failures (ASI08) | a failed step stops the run; at most 5 filters per run |
| Trust exploitation (ASI09) | model text labelled "unverified"; exact conditions shown |
| Rogue agents (ASI10) | transcripts; proxy log; marked, removable filters; `DISABLED` kill switch |
| Information disclosure (LLM02) | no raw events; no keys; identifying values pseudonymized; local sanitizer |
| Data poisoning (LLM04) | code checks refuse shells, LOL binaries, user-writable and container paths |
| Output handling (LLM05) | output parsed as JSON against schemas |
| Unbounded consumption (LLM10) | turn, time, call and token limits |

### Sanitization

**Pseudo** (`agent/pseudo.py`) replaces identifying values with stand-ins such as `host-1.lan` and `user-1`, and maps the stand-ins back in the model's tool calls and filters. Every run keeps a transcript of what went to the inference provider.

**Pseudo** is limited to known values: your settings, the user and host names in Elasticsearch, and its patterns for IPs, MACs and secrets. Set your domains in `NOISE_INTERNAL_DOMAINS` and your host names in `NOISE_INTERNAL_HOSTNAMES` (`agent.env`, comma separated).

Domains are replaced anywhere, even joined to other text. Host names are replaced wherever no letter touches them: `nas` in `backup-nas.sh` or `nas2`, but not in `canasta`.

An identifier that appears once in a command line is replaced only if **Sanitize** names it. Set `NOISE_SANITIZER_URL` and `NOISE_SANITIZER_MODEL` (`agent.env`) to a model already loaded on your own Ollama. Ollama.com, public addresses and `:cloud` models are refused, and if it doesn't answer, nothing is sent.

Each request to **Sanitize** starts with a fake canary line, with user and host names new for every request. If the answer leaves them out, something likely told the model to stay quiet: the batch is split in half until that line is found, and it is sanitized only by **Pseudo**.

| Value | Stand-in |
|---|---|
| host names | `host-1.lan` |
| internal domains (`NOISE_INTERNAL_DOMAINS`), and names under them | `site-1.lan`, `host-2.lan` |
| host names you list (`NOISE_INTERNAL_HOSTNAMES`), wherever no letter touches them | `value-1` |
| user names | `user-1` |
| private and public IPs | `198.18.0.1`, `240.0.0.1` |
| domains, except well-known vendors | `domain-1.org` |
| secrets, MAC addresses, IDs in URLs | `secret-1`, `02:00:00:00:00:01`, `900000001` |

### Deterministic checks

Each filter has to pin the process by its full path or exact command line, with an exact `event.category`. Tier 1 LOL binaries (`attacker_tools` in `safety.json`: curl, nc, ssh, debuggers, ...) are never filtered, not even by exact command line. Tier 2 (`lolbins`: the LOLBAS, GTFOBins and LOOBins catalogues) are allowed only by exact command line.

Also refused: user-writable, relative, container and persistence paths, a command line naming a URL, IP or host, and process IDs. Bursts are refused: over half the events in one hour, or all of them within 3 hours. If approved filters overlap, only the narrowest is created, up to 5 per run.

### Models

In November 2026, `deepseek-v4.1-flash:1017` replaced `deepseek-v4-pro:0813` for **Validate**: it caught more simulated attacks at a quarter of the cost. `kimi-k3` stays on **Propose**, outside the DeepSeek family.

End to end, the agent hid none of 45 simulated attacks or 54 replayed macOS attacks. The code, not the second model, is the hard control: in testing, every **Validate** model approved at least one unsafe filter.

**Sanitize** was tested with `llama3.3:70b` on a local GPU in a full dry run (644 lines sent, ~17 minutes): no private name or IP was sent, the patterns caught the public IPs and names it missed, and it found nothing the patterns didn't (its job, names the patterns can't know, is untested on real unknown host names). Each run's `sanitizer.propose.json` and `sanitizer.validate.json` show what the model named, what was new to the patterns, and what only the patterns caught.

## Metrics

`metrics/` measures every Elastic Defend event filter, whoever made it: each filter's events/day before creation, what still matches, and the difference in GB/day and $/month at the ingest rate on your Elastic Cloud bill, plus the daily bill and events per day, written to InfluxDB for Grafana. No model and only read-only keys, so it runs without containers.

Setup (Python 3, flock, InfluxDB v2):

- Create the keys (API Keys below): the metrics key in `metrics/config/read.env` as `ELASTIC_API_KEY=<key>`, an Elastic Cloud key, an InfluxDB token with write and read on the bucket, and optionally a Grafana Editor token.
- `cp metrics/config/metrics.env.example metrics/config/metrics.env`, then set `ELASTIC_URL`, `INFLUXDB_*`, `EC_API_KEY` and, for a private CA, `INFLUXDB_CA_FILE`. `chmod 600 metrics/config/*.env`.
- Backfill once, then run daily:

```
metrics/run.sh --days 7 --billing-days 90       # once: backfill
metrics/run.sh                                  # daily; log in metrics/runs/
python3 metrics/noise-metrics.py --verify       # what InfluxDB holds
```

- Schedule it, e.g. cron: `0 6 * * * /path/to/metrics/run.sh`, or the systemd timer in `metrics/deploy/`.
- In Grafana, import `metrics/grafana/noise-cut-dashboard.json` with an InfluxDB data source set to Flux, or set `GRAFANA_*` and run `python3 metrics/noise-metrics.py --push-dashboard`.

## API Keys

| Key | Used by | Permissions |
|---|---|---|
| read-only | agent | read `logs-*` |
| event filter | agent, Human mode | read `logs-*`; Kibana Event Filters: All; Global artifact management: All |
| metrics | metrics | read `logs-*`; Kibana Security: Event Filters: Read |
| Elastic Cloud | metrics | Viewer on the security project, Cloud API access only |

Create Elastic keys with "Control security privileges" turned on and an expiry date. Keys without restrictions are refused.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
