# resolver-inventory

Aggregate, validate, score, and export public DNS and DoH resolvers.

## Features

- **Multi-source discovery** – plain DNS from public-dns.info, DoH from curl wiki and AdGuard providers, manual seed files
- **Full endpoint metadata** – DoH records preserve URL, host, port, path, TLS server name, bootstrap IPs, and provenance
- **Active validation** – reachability, NXDOMAIN fidelity, latency, consistency, TLS validity
- **Pluggable test corpus** – controlled authoritative zone (best) or low-variance public fallback
- **Scored output** – `accepted` / `candidate` / `rejected` with machine-readable reason codes
- **Multiple export formats** – JSON, plain text, dnsdist config, Unbound forward-zone
- **Deterministic CI** – required PR checks use local ephemeral fixtures, never public resolvers

## Quick start

```bash
# Install with uv
uv sync --group dev

# Full pipeline (discover → validate → export)
resolver-inventory refresh --config configs/default.toml --output outputs/latest

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
resolver-inventory export json     [--input FILE] [--output FILE]
resolver-inventory export text     [--input FILE] [--output FILE]
resolver-inventory export dnsdist  [--input FILE] [--output FILE]
resolver-inventory export unbound  [--input FILE] [--output FILE]
```

Global flags: `--config FILE`, `--log-level {DEBUG,INFO,WARNING,ERROR}`

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

Copy `configs/default.toml` and edit. Config format is **TOML** (stdlib `tomllib`, no extra deps):

```toml
[[sources.dns]]
type = "publicdns_info"        # fetch from public-dns.info CSV

[[sources.dns]]
type = "manual"
path = "configs/manual-dns.txt"

[[sources.doh]]
type = "curl_wiki"             # scrape curl's DoH providers page

[[sources.doh]]
type = "adguard"               # fetch AdGuard providers JSON

[[sources.doh]]
type = "manual"
path = "configs/manual-doh.toml"

[validation]
rounds = 3
timeout_ms = 2000
parallelism = 50

[validation.corpus]
mode = "controlled"            # "controlled" or "fallback"
zone = "dns-test.example.net"  # your controlled zone (controlled mode only)

[scoring]
accept_min_score = 80
candidate_min_score = 60

[export]
formats = ["json", "text", "dnsdist"]
output_dir = "outputs/latest"
```

### Corpus modes

| Mode | Description |
|---|---|
| `controlled` | Uses your own authoritative zone with fixed RRs. Best accuracy. Requires `zone` to be set. |
| `fallback` | Uses low-variance public infrastructure names (root-server hostnames, IANA NS). No zone needed. |

### Validation reason codes

| Code | Meaning |
|---|---|
| `nxdomain_spoofing` | Resolver returned NOERROR for a nonexistent name |
| `tls_name_mismatch` | DoH TLS certificate does not match the expected server name |
| `timeout_rate_high` | More than 50% of probes timed out |
| `latency_p95_high` | 95th-percentile latency exceeds 2 s |
| `unexpected_nxdomain` | Resolver returned NXDOMAIN for a name that should exist |
| `unexpected_rcode` | Resolver returned an unexpected RCODE |
| `udp_only` | Only UDP probes ran (no TCP confirmation) |

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

# Type-check (requires Python 3.14 stable; mypy's C extensions crash on 3.14a6)
uv run mypy src

# Build the package
uv build
```

> **Note:** `mypy` uses C extensions that segfault on CPython 3.14a6. Type-checking
> is enforced in CI against 3.14 stable. Locally on 3.14a6 it can be skipped.

## Package layout

```
src/resolver_inventory/
  __init__.py          # public re-exports
  cli.py               # CLI entry point
  models.py            # Candidate, ProbeResult, ValidationResult
  settings.py          # config loading
  sources/             # discovery adapters
  normalize/           # deduplication and cleanup
  validate/            # probing, corpus, scoring
  export/              # JSON, text, dnsdist, unbound
  util/                # logging, HTTP, DNS packets, timing
tests/
  unit/                # pure unit tests (no I/O)
  integration/         # local-fixture tests (marked "integration")
  fixtures/            # authoritative DNS, spoofing DNS, DoH+TLS servers
configs/               # default config and seed files
```

## CI

- **`ci.yml`** – lint, type-check, unit tests (matrix: Linux/macOS/Windows), integration tests, build
- **`release.yml`** – builds and publishes to PyPI via trusted publishing on `v*` tags
- **`refresh.yml`** – nightly pipeline run + optional non-blocking canary network tests

Required PR checks never touch public resolvers.

## Non-goals for v1

- DNSCrypt, DoQ, Oblivious DoH
- Browser fingerprinting or provider privacy scoring
- Full ECS classification
- Internet-scale scanning
- Auto-promotion of newly discovered endpoints into a production allowlist

## License

MIT © disposable
