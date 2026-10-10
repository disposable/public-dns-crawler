# Public DNS, DoT, DoQ, and DoH resolver crawler

Aggregate, validate, score, and export public DNS, DoT, DoQ, and DoH resolvers.

## Features

- **Multi-source discovery** - plain DNS from public-dns.info, the AdGuard provider list, and the paulmillr/encrypted-dns profiles; DoH from the curl wiki, AdGuard, DNSCrypt resolver lists (public-resolvers, parental-control, OpenNIC), paulmillr, and the dibdot DoH blocklists; DoT from AdGuard, paulmillr, and dibdot; DoQ from the AdGuard provider list; manual seed files
- **Pre-validation filtering records** - source and normalization drops are exported as `filtered.json` with reason codes
- **Full endpoint metadata** - DoH records preserve URL, host, port, path, TLS server name, bootstrap IPs, and provenance; DoT/DoQ records preserve host, port, TLS server name, and bootstrap IPs
- **Active validation** - reachability, NXDOMAIN fidelity, latency, consistency, TLS validity
- **Capability tags** - non-scoring measurements (DNSSEC validation, ECS support, filtering detection) exported as a `capabilities` object per result
- **Pluggable test corpus** - controlled zone, local external JSON corpus, or tiny built-in fallback
- **Scored output** - component-based scoring (correctness, availability, performance, history) with separate confidence score, score caps, and derived metrics
- **Multiple export formats** - JSON, plain text, dnsdist config, Unbound forward-zone

## Source feeds

Default discovery sources configured in `configs/default.toml`:

- `publicdns_info` (plain DNS): <https://public-dns.info/nameservers.csv>
  - default filter: `min_reliability = 0.50`
- `adguard` (plain DNS): same providers markdown, `DNS, IPv4`/`DNS, IPv6` rows
- `curl_wiki` (DoH): <https://raw.githubusercontent.com/wiki/curl/curl/DNS-over-HTTPS.md>
- `adguard` (DoH): <https://raw.githubusercontent.com/AdguardTeam/KnowledgeBaseDNS/master/docs/general/dns-providers.md>
- `adguard` (DoT): same AdGuard providers markdown, `tls://` rows (including `Hostname:`/`IP:`-prefixed cells; `IP:`/`IPv6:` fields become bootstrap addresses)
- `adguard` (DoQ): same AdGuard providers markdown, `quic://` rows
- `dnscrypt` (DoH/DoT/DoQ/plain): <https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md> - `sdns://` stamps decoded per the DNS Stamps spec; enabled for `doh` by default. Any file in the same format can be used via `url`; `label` overrides the recorded `source` name. The default config also enables the `parental-control.md` and `opennic.md` sibling lists
- `paulmillr` (plain DNS/DoH/DoT): <https://github.com/paulmillr/encrypted-dns> - per-provider JSON profiles under `src/`, enumerated via the GitHub contents API. Variant `https`/`tls` endpoints plus `ServerAddresses` (also used as bootstrap IPs); variant `region`/`censorship` flow into candidate metadata
- `dibdot` (DoH/DoT): <https://github.com/dibdot/DoH-IP-blocklists> - `doh-domains.txt` becomes `https://<domain>/dns-query` candidates; `doh-ipv4.txt`/`doh-ipv6.txt` `# hostname` comments become DoT candidates with the listed IPs as bootstrap addresses, plus DoH guesses for each commented hostname. Aggregate blocklist data - expect a lower hit rate; validation does the filtering
- `manual` seeds (local files):
  - `configs/manual-dns.txt`
  - `configs/manual-doh.toml`
  - `configs/manual-dot.toml`
  - `configs/manual-doq.toml` (same schema as manual-dot)

## Quick start

```bash
# Install with uv
uv sync --group dev

# Full pipeline (discover → validate → export)
uv run resolver-inventory refresh --config configs/default.toml --output outputs/latest

# Full pipeline with an external local probe corpus
uv run resolver-inventory refresh \
  --config configs/default.toml \
  --probe-corpus tests/fixtures/probe-corpus-valid.json \
  --output outputs/latest

# Validate a corpus file before using it
uv run resolver-inventory validate-probe-corpus --input tests/fixtures/probe-corpus-valid.json

# Inspect exported files
cat outputs/latest/accepted.json
cat outputs/latest/resolvers.txt
cat outputs/latest/dnsdist.conf
```

## CLI

```
resolver-inventory discover   # gather raw candidates
resolver-inventory validate   # run probes, emit scored records
resolver-inventory refresh    # full pipeline (discover + validate + export)
resolver-inventory split-candidates     # deterministic candidate sharding
resolver-inventory materialize-results  # merge validated shards and export outputs
resolver-inventory validate-probe-corpus --input FILE
resolver-inventory generate-probe-corpus [--config FILE] [--seed-file FILE] [--output DIR]
resolver-inventory export json     [--input FILE] [--output FILE]
resolver-inventory export text     [--input FILE] [--output FILE]
resolver-inventory export dnsdist  [--input FILE] [--output FILE]
resolver-inventory export unbound  [--input FILE] [--output FILE]
```

Global flags: `--config FILE`, `--log-level {DEBUG,INFO,WARNING,ERROR}`.

Validation commands also support `--probe-corpus FILE`, `--validation-parallelism N`, `--dns-backend {python,massdns}`, `--massdns-bin PATH`, `--massdns-hashmap-size N`, `--history-db FILE`, and `--run-date YYYY-MM-DD`. When `--probe-corpus` is provided, the CLI sets `validation.corpus.mode = "external"` and loads probes from that local JSON file. `--history-db` opens the history database read-only so shard jobs can score against shared history without locking it.
JSON exports are written in compact form and sorted deterministically by endpoint identity to keep diffs stable.
Use `--split-json-max-bytes N` on `refresh`, `materialize-results`, or `export json` to split large JSON outputs into `.part-XXXX` files.

### Staged pipeline commands

For multi-VM flows (for example GitHub Actions matrix validation), use:

1. `discover --output candidates.json --filtered-output filtered.json`
2. `split-candidates --input candidates.json --output-dir chunks --shards 10`
3. `validate --input chunks/chunk-XX.json --output shard-XX.json`
4. `materialize-results --inputs-glob "shards/*.json" --filtered-input filtered.json --output outputs/latest`

### Exported file meanings

- `accepted.json` - resolvers with status `accepted`
- `candidate.json` - resolvers with status `candidate`
- `rejected.json` - resolvers with status `rejected`; only failed probes are kept, and `all_probes_failed` is set when every probe failed
- `filtered.json` - candidates dropped before validation, including source filtering, normalization failures, duplicates, and historical quarantine
- `resolvers.txt` - accepted plain DNS resolvers only, as `host:port`
- `resolvers-doh.txt` - accepted DoH resolvers only, as full HTTPS endpoints
- `resolvers-dot.txt` - accepted DoT resolvers only, as `tls://host[:port][#tls-name]`
- `resolvers-doq.txt` - accepted DoQ resolvers only, as `quic://host[:port][#tls-name]`
- `dnsdist.conf` - dnsdist backends for all non-rejected resolvers (plain DNS, DoT, and DoH sections; dnsdist has no DoQ backend protocol, so DoQ resolvers appear only in text/JSON exports)
- `unbound-forward.conf` - accepted plain DNS resolvers rendered as Unbound forward zones
- `unbound-forward-dot.conf` - accepted DoT resolvers rendered as an Unbound TLS forward zone (`forward-tls-upstream: yes`)

If `--split-json-max-bytes` is used, large JSON outputs are written as `name.part-XXXX.json` chunks instead of a single large file.

## Library API

```python
from resolver_inventory.sources import discover_candidates
from resolver_inventory.validate import validate_candidates
from resolver_inventory.export import export_dnsdist, export_json
from resolver_inventory.settings import load_settings

settings = load_settings("configs/default.toml")
candidates = discover_candidates(settings)
results = validate_candidates(candidates, settings)
print(export_json(results))
```

## Configuration

Copy `configs/default.toml` and edit. Config format is **TOML** (stdlib
`tomllib`, no extra deps). The full reference - all `sources.*` entries,
`validation`, `capabilities`, the optional `massdns` backend, corpus modes,
`scoring`, and `export` - lives in
[HOW_IT_WORKS](HOW_IT_WORKS.md#configuration-reference).

## Validation and scoring internals

The validation pipeline (corpus modes, per-transport probe flow, reason
codes), the scoring model, and the exported JSON field reference are
documented in [HOW_IT_WORKS](HOW_IT_WORKS.md):

- [Validation flow and reason codes](HOW_IT_WORKS.md#validation-flow)
- [Scoring system and caps](HOW_IT_WORKS.md#scoring-system)
- [Exported score fields](HOW_IT_WORKS.md#exported-score-fields)

## Development

```bash
# Install dev dependencies
uv sync --group dev

# Run all tests
uv run pytest

# Run only unit tests (fast, no I/O)
uv run pytest tests/unit

# Run only integration tests (local fixtures, no public network)
uv run pytest -m integration tests/integration

# Lint
uv run ruff check .
uv run ruff format .

# Type-check (Python 3.13.x)
uv run pyright

# Build the package
uv build
```

All local test commands in this repository are expected to run through `uv run ...` after
`uv sync --group dev`. No manual `PYTHONPATH=src` bootstrap is required.

## Probe Corpus Docker Flow

The probe corpus generator can run in Docker and write its artifacts into
`outputs/probe-corpus/`.

```bash
# Build the generator image
make probe-corpus-build-image

# Generate the corpus into outputs/probe-corpus/
make probe-corpus-generate

# Validate the generated JSON corpus
make probe-corpus-validate

# Run the normal resolver refresh with that generated corpus
make refresh-with-probe-corpus
```

Equivalent direct Docker invocation:

```bash
mkdir -p outputs/probe-corpus
docker build -f docker/probe-corpus.Dockerfile -t resolver-inventory-probe-corpus .
docker run --rm -v "$PWD/outputs/probe-corpus:/out" resolver-inventory-probe-corpus
uv run resolver-inventory validate-probe-corpus \
  --config configs/probe-corpus.toml \
  --input outputs/probe-corpus/probe-corpus.json \
  --schema-version 2
uv run resolver-inventory refresh \
  --config configs/default.toml \
  --probe-corpus outputs/probe-corpus/probe-corpus.json \
  --output outputs/latest
```

## CI

- **`ci.yml`** - lint, type-check, unit tests (matrix: Linux/macOS/Windows), integration tests, build
- **`release.yml`** - builds and publishes to PyPI via trusted publishing on `v*` tags
- **`refresh.yml`** - scheduled/manual multi-job pipeline:
  1. build the Docker probe-corpus generator
  2. generate `outputs/probe-corpus/probe-corpus.json`
  3. validate the generated corpus
  4. pass `probe-corpus` to the refresh job as a workflow artifact
  5. run `refresh --probe-corpus ...`
  6. upload `refreshed-resolver-data`
  7. run optional non-blocking network canaries

Required PR checks never touch public resolvers.

## History and reporting scripts

These helper scripts are used by the parent data repo workflow and are intentionally separate from the main CLI:

- `scripts/apply_history_quarantine.py` - drops currently quarantined plain DNS hosts from discovered candidates and appends `historical_dns_quarantine` entries to `filtered.json`
- `scripts/update_history.py` - updates `meta/history.duckdb` from `validated.json`, `filtered.json`, and build metadata
- `scripts/generate_changelog.py` - diffs the two most recent runs in `meta/history.duckdb` and writes `meta/changelog.json` (added, removed, and status-transition records)
- `scripts/generate_stats_report.py` - regenerates the `<!-- GENERATED_STATS_* -->` README statistics section from history data, including the latest-run changelog summary
- `scripts/analyze_scores.py` - analyzes score distribution from validation results and can compare before/after runs
- `scripts/analyze_history.py` - inspects history database and prints diagnostics about resolver history coverage

## History System

The crawler maintains historical data in `meta/history.duckdb` using DuckDB. The history system tracks resolver status over time to support:

1. **Score history caps** - resolvers with insufficient observation history get capped scores
   and, when `revalidation_stable_days` is enabled, resolvers with sustained accepted
   history get probed with fewer rounds
2. **DNS host quarantine** - hosts rejected for 14+ consecutive days are temporarily excluded
3. **Stability metrics** - streaks, flapping detection, and success rate tracking

### Schema Overview

The history database uses the current schema with these tables:

**runs** - Run-level metadata with unique `run_id` supporting multiple runs per day:
- `run_id`, `run_date`, `run_started_at`, `generated_at`
- `github_run_id`, `repo_sha`, `crawler_sha`, `run_type`

**resolver_run_status** - Per-resolver status for each run (allows intra-day runs):
- `run_id`, `resolver_key`, `host`, `transport`, `endpoint_url`, `port`, `path`
- `status`, `reasons_signature`, `reasons_json`
- `accepted_probe_count`, `failed_probe_count`, `total_probe_count`
- `p50_latency_ms`, `p95_latency_ms`, `jitter_ms`

**resolver_daily** - Daily rollup aggregating all runs per day:
- `run_date`, `resolver_key`, `host`, `transport`
- `day_status`, `reasons_signature`, `reasons_json`
- `runs_that_day`, `successful_runs_that_day`, `failed_runs_that_day`
- `flapped_within_day`
- `p50_latency_ms`, `p95_latency_ms`, `jitter_ms`

**dns_host_quarantine** - Host-level DNS quarantine state derived from `resolver_daily`:
- `host`, `first_quarantined_on`, `last_quarantined_on`, `retry_after`
- `reasons_signature`, `reasons_json`, `cycles`

### Resolver Identity (resolver_key)

History is tracked per-endpoint using a canonical `resolver_key`:

- **DNS UDP**: `dns-udp|host|port` (e.g., `dns-udp|1.1.1.1|53`)
- **DNS TCP**: `dns-tcp|host|port` (e.g., `dns-tcp|1.1.1.1|53`)
- **DoT**: `dot|host|port` (e.g., `dot|dns.quad9.net|853`), or
  `dot|host|port|tls_name` when the TLS authentication name differs from
  the connect host (e.g., `dot|9.9.9.9|853|dns.quad9.net`)
- **DoQ**: `doq|host|port`, or `doq|host|port|tls_name` (same rules as DoT)
- **DoH**: `doh|url` (e.g., `doh|https://dns.example.com/dns-query`)

This allows:
- Same host on different transports to have independent history
- Different DoH endpoints on same host to be tracked separately
- Accurate per-endpoint scoring and caps

### History Availability

Validation consults history when `--history-db` is provided (read-only). Scoring distinguishes between:
- **No history database**: history analysis is skipped entirely (no history score/caps/reasons).
- **No history rows for a resolver**: the resolver counts as zero observed runs and the `<3 runs` cap applies.
- **Sparse existing history**: history-based caps and stability logic can still apply.
- **Meaningful history**: full history scoring behavior applies.

### Intra-day Run Support

The schema supports multiple validation runs per day:
- Multiple entries in `runs` with same `run_date` but different `run_id`
- Multiple entries in `resolver_run_status` per run
- `resolver_daily` aggregates all runs for a day into one row
- History counting uses distinct days, not raw run counts

This allows future 4x/day scheduling without inflating "days of history" counts.

## License

MIT © disposable
