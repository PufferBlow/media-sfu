#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

DEFAULT_UNIT_TEST_PATTERN="./..."
DEFAULT_BENCH_PATTERN="BenchmarkMediaSFUSignalingJoin"
DEFAULT_BENCH_TIME="5x"
DEFAULT_RUN_STRESS="0"
DEFAULT_STRESS_CLIENTS="128"
DEFAULT_STRESS_TEST_PATTERN="TestMediaSFUSignalingStress"
DEFAULT_RUN_SOAK="0"
DEFAULT_SOAK_CLIENTS="32"
DEFAULT_SOAK_DURATION_SECONDS="30"
DEFAULT_SOAK_HOLD_MILLISECONDS="250"
DEFAULT_SOAK_TEST_PATTERN="TestMediaSFUSignalingSoak"

UNIT_TEST_PATTERN="${UNIT_TEST_PATTERN:-$DEFAULT_UNIT_TEST_PATTERN}"
BENCH_PATTERN="${BENCH_PATTERN:-$DEFAULT_BENCH_PATTERN}"
BENCH_TIME="${BENCH_TIME:-$DEFAULT_BENCH_TIME}"
RUN_STRESS="${RUN_STRESS:-$DEFAULT_RUN_STRESS}"
STRESS_CLIENTS="${STRESS_CLIENTS:-$DEFAULT_STRESS_CLIENTS}"
STRESS_TEST_PATTERN="${STRESS_TEST_PATTERN:-$DEFAULT_STRESS_TEST_PATTERN}"
RUN_SOAK="${RUN_SOAK:-$DEFAULT_RUN_SOAK}"
SOAK_CLIENTS="${SOAK_CLIENTS:-$DEFAULT_SOAK_CLIENTS}"
SOAK_DURATION_SECONDS="${SOAK_DURATION_SECONDS:-$DEFAULT_SOAK_DURATION_SECONDS}"
SOAK_HOLD_MILLISECONDS="${SOAK_HOLD_MILLISECONDS:-$DEFAULT_SOAK_HOLD_MILLISECONDS}"
SOAK_TEST_PATTERN="${SOAK_TEST_PATTERN:-$DEFAULT_SOAK_TEST_PATTERN}"

usage() {
  cat <<'EOF'
Usage: ./scripts/run_test.sh [--heavy] [--stress] [--soak] [--help]

Options:
  --heavy   Run a larger benchmark/stress preset suitable for manual benchmarking.
  --stress  Enable the stress test with the current or preset client count.
  --soak    Enable the soak test with the current or preset duration/client count.
  --help    Show this help text.

Environment overrides:
  UNIT_TEST_PATTERN
  BENCH_PATTERN
  BENCH_TIME
  RUN_STRESS
  STRESS_CLIENTS
  STRESS_TEST_PATTERN
  RUN_SOAK
  SOAK_CLIENTS
  SOAK_DURATION_SECONDS
  SOAK_HOLD_MILLISECONDS
  SOAK_TEST_PATTERN
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --heavy)
      if [[ "${BENCH_TIME}" == "${DEFAULT_BENCH_TIME}" ]]; then
        BENCH_TIME="25x"
      fi
      if [[ "${STRESS_CLIENTS}" == "${DEFAULT_STRESS_CLIENTS}" ]]; then
        STRESS_CLIENTS="512"
      fi
      if [[ "${SOAK_CLIENTS}" == "${DEFAULT_SOAK_CLIENTS}" ]]; then
        SOAK_CLIENTS="128"
      fi
      if [[ "${SOAK_DURATION_SECONDS}" == "${DEFAULT_SOAK_DURATION_SECONDS}" ]]; then
        SOAK_DURATION_SECONDS="120"
      fi
      RUN_STRESS=1
      RUN_SOAK=1
      ;;
    --stress)
      RUN_STRESS=1
      ;;
    --soak)
      RUN_SOAK=1
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
  shift
done

cd "${REPO_ROOT}"

echo "==> Running media-sfu unit tests"
go test "${UNIT_TEST_PATTERN}"

echo "==> Running media-sfu benchmark: pattern=${BENCH_PATTERN} benchtime=${BENCH_TIME}"
go test ./cmd/server -run '^$' -bench "${BENCH_PATTERN}" -benchtime="${BENCH_TIME}"

if [[ "${RUN_STRESS}" == "1" ]]; then
  echo "==> Running media-sfu stress test: clients=${STRESS_CLIENTS}"
  MEDIA_SFU_STRESS=1 \
  MEDIA_SFU_STRESS_CLIENTS="${STRESS_CLIENTS}" \
  go test ./cmd/server -run "${STRESS_TEST_PATTERN}" -v
else
  echo "==> Skipping stress test (--stress to enable)"
fi

if [[ "${RUN_SOAK}" == "1" ]]; then
  echo "==> Running media-sfu soak test: clients=${SOAK_CLIENTS} duration=${SOAK_DURATION_SECONDS}s hold=${SOAK_HOLD_MILLISECONDS}ms"
  MEDIA_SFU_SOAK=1 \
  MEDIA_SFU_SOAK_CLIENTS="${SOAK_CLIENTS}" \
  MEDIA_SFU_SOAK_DURATION_SECONDS="${SOAK_DURATION_SECONDS}" \
  MEDIA_SFU_SOAK_HOLD_MILLISECONDS="${SOAK_HOLD_MILLISECONDS}" \
  go test ./cmd/server -run "${SOAK_TEST_PATTERN}" -v
else
  echo "==> Skipping soak test (--soak to enable)"
fi
