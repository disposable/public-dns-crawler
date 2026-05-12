#!/usr/bin/env bash
# Smoke test for the massdns validation backend.
# Validates 10k dns-udp:53 candidates and reports a pass/fail summary.
#
# Usage (from the crawler directory):
#   scripts/smoke_massdns.sh [--massdns-bin PATH] [--work-dir PATH]
#
# Defaults:
#   --massdns-bin  massdns  (must be on PATH or provide an absolute path)
#   --work-dir     /tmp/smoke-massdns

set -euo pipefail

# Ensure uv is on PATH (handles installs in ~/.local/bin not yet in PATH)
export PATH="$HOME/.local/bin:$PATH"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRAWLER_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

MASSDNS_BIN="${SMOKE_MASSDNS_BIN:-massdns}"
WORK_DIR="${SMOKE_WORK_DIR:-/tmp/smoke-massdns}"
INPUT="${SMOKE_INPUT:-$CRAWLER_DIR/smoke-test-input.json}"
PROBE_CORPUS="${SMOKE_PROBE_CORPUS:-}"
UV_ENV="${UV_PROJECT_ENVIRONMENT:-}"

log()  { printf '[smoke-massdns] %s\n' "$*"; }
die()  { printf '[smoke-massdns] ERROR: %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --massdns-bin) MASSDNS_BIN="${2:?}"; shift 2 ;;
    --work-dir)    WORK_DIR="${2:?}";    shift 2 ;;
    --input)       INPUT="${2:?}";       shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

# Resolve massdns binary
if [[ "$MASSDNS_BIN" == */* ]]; then
  [[ -x "$MASSDNS_BIN" ]] || die "massdns binary not executable: $MASSDNS_BIN"
else
  command -v "$MASSDNS_BIN" >/dev/null 2>&1 || \
    die "massdns not found on PATH; use --massdns-bin or set SMOKE_MASSDNS_BIN"
fi

[[ -f "$INPUT" ]] || die "input file not found: $INPUT"

INPUT_COUNT="$(python3 -c "import json,sys; print(len(json.load(open(sys.argv[1]))))" "$INPUT")"
log "Input: $INPUT ($INPUT_COUNT candidates)"
log "MassDNS binary: $MASSDNS_BIN ($($MASSDNS_BIN --version 2>&1 | head -1))"

# Prepare working directory
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"

OUTPUT="$WORK_DIR/results.json"

# Locate or generate probe corpus
if [[ -z "$PROBE_CORPUS" ]]; then
  if [[ -f "$CRAWLER_DIR/../probe-corpus/probe-corpus.json" ]]; then
    PROBE_CORPUS="$(realpath "$CRAWLER_DIR/../probe-corpus/probe-corpus.json")"
    log "Using existing probe corpus: $PROBE_CORPUS"
  else
    log "Generating probe corpus (no existing corpus found)"
    PROBE_CORPUS="$WORK_DIR/probe-corpus.json"
    UV_PROJECT_ENVIRONMENT="$UV_ENV" uv run resolver-inventory generate-probe-corpus \
      --config "$CRAWLER_DIR/configs/probe-corpus.toml" \
      --output "$WORK_DIR/probe-corpus-dir"
    cp "$WORK_DIR/probe-corpus-dir/probe-corpus.json" "$PROBE_CORPUS"
  fi
fi

log "Starting massdns validation of $INPUT_COUNT candidates..."
START_TS="$(date +%s)"

# Write a smoke-test TOML config: 500 ms timeout so the AAAA/NS session
# timeout scales to ~5 min (2s default would give ~20 min for 10k servers).
SMOKE_CONFIG="$WORK_DIR/smoke.toml"
cat >"$SMOKE_CONFIG" <<'TOML'
[validation]
timeout_ms = 500
rounds = 3
parallelism = 1

[validation.dns_backend]
kind = "massdns"
fallback_to_python_on_error = true
batch_max_queries = 50000
# Disable predictable mode: with it massdns processes one query at a time
# which turns a 5-minute AAAA session into a 20+ minute one.
predictable = false
TOML

(
  cd "$CRAWLER_DIR"
  UV_PROJECT_ENVIRONMENT="${UV_ENV:-}" uv run resolver-inventory validate \
    --config "$SMOKE_CONFIG" \
    --input "$INPUT" \
    --probe-corpus "$PROBE_CORPUS" \
    --dns-backend massdns \
    --massdns-bin "$MASSDNS_BIN" \
    --validation-parallelism 1 \
    --progress-every 500 \
    --output "$OUTPUT"
)

END_TS="$(date +%s)"
ELAPSED=$(( END_TS - START_TS ))

log "Validation finished in ${ELAPSED}s"
log "Output: $OUTPUT"

# Summarise results
python3 - "$OUTPUT" <<'PYEOF'
import json, sys, pathlib

data = json.loads(pathlib.Path(sys.argv[1]).read_text())
accepted  = [e for e in data if e.get("accepted")]
candidate = [e for e in data if not e.get("accepted") and e.get("status") == "candidate"]
rejected  = [e for e in data if not e.get("accepted") and e.get("status") == "rejected"]

print(f"\n{'='*55}")
print(f"  SMOKE TEST RESULTS")
print(f"{'='*55}")
print(f"  Total validated : {len(data)}")
print(f"  Accepted        : {len(accepted)}")
print(f"  Candidate       : {len(candidate)}")
print(f"  Rejected        : {len(rejected)}")
if data:
    print(f"  Accept rate     : {100*len(accepted)/len(data):.1f}%")

# Check for signs of massdns failure (all probes marked as unmatched/timeout)
timeout_errors = sum(
    1 for e in data
    for probe in e.get("probes", [])
    if isinstance(probe.get("error"), str) and "massdns_unmatched" in probe["error"]
)
total_probes = sum(len(e.get("probes", [])) for e in data)
print(f"  Total probes    : {total_probes}")
print(f"  massdns_unmatched probes: {timeout_errors} ({100*timeout_errors/max(total_probes,1):.1f}%)")
print(f"{'='*55}\n")

if total_probes == 0:
    print("FAIL: no probes recorded — massdns produced no output")
    sys.exit(1)
if timeout_errors == total_probes:
    print("FAIL: every probe returned massdns_unmatched — massdns backend is broken")
    sys.exit(1)
if timeout_errors / max(total_probes, 1) > 0.95:
    print(f"WARN: {100*timeout_errors/total_probes:.1f}% of probes unmatched — massdns may have a problem")
    sys.exit(1)
print("PASS: massdns backend produced valid results")
PYEOF
