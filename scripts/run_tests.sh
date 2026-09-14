#!/bin/bash
#
# Usage: ./scripts/run_tests.sh [--unit-only] [--e2e-only] [--keep-bridge] [--filter PATTERN]
#                               [--build-dir DIR] [--bridge-image IMAGE] [--dataset-dir DIR]
#                               [--e2e-workers N]

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

BUILD_DIR="build"
BRIDGE_IMAGE="hub.simplito.com/privmx/privmx-bridge:dev"
DATASET_DIR="test/env/datasets/Dataset"
E2E_WORKERS=4
RUN_UNIT=1
RUN_E2E=1
KEEP_BRIDGE=0
FILTER=""

usage() {
    cat <<EOF
Usage: $0 [options]

  --unit-only            Run only the unit tests (no Docker required)
  --e2e-only             Run only the e2e tests (requires Docker)
  --keep-bridge          Leave the Bridge docker containers running after the e2e run
  --filter PATTERN       Run only tests matching the GTest pattern (also: --test)
  --build-dir DIR        Build directory to look for test binaries in (default: build)
  --bridge-image IMAGE   Bridge image used for e2e tests (default: $BRIDGE_IMAGE)
  --dataset-dir DIR      Dataset used to seed the Bridge for e2e tests (default: $DATASET_DIR)
  --e2e-workers N        Number Workers running e2e tests (default: $E2E_WORKERS)
  -h, --help          Show this help

Examples:
  $0 --unit-only --filter 'TreeKeysTest.*'
  $0 --e2e-only --filter 'GroupTest.CreateGroup'
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --unit-only) RUN_E2E=0; shift ;;
        --e2e-only) RUN_UNIT=0; shift ;;
        --keep-bridge) KEEP_BRIDGE=1; shift ;;
        --filter|--test) FILTER="$2"; shift 2 ;;
        --build-dir) BUILD_DIR="$2"; shift 2 ;;
        --dataset-dir) DATASET_DIR="$2"; shift 2 ;;
        --bridge-image) BRIDGE_IMAGE="$2"; shift 2 ;;
        --e2e-workers) E2E_WORKERS="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

GTEST_FILTER_ARGS=()
[[ -n "$FILTER" ]] && GTEST_FILTER_ARGS+=("--gtest_filter=$FILTER")

UNIT_FAILED=0
E2E_FAILED=0
UNIT_TIME=0
E2E_TIME=0

fmt_time() { printf '%02d:%02d:%02d' $(($1 / 3600)) $(($1 % 3600 / 60)) $(($1 % 60)); }

if [[ "$RUN_UNIT" -eq 1 ]]; then
    echo "=== Unit tests ==="
    UNIT_START=$SECONDS
    UNIT_BINARIES=()
    for bin in \
        "$BUILD_DIR/utils/privmxutils_test" \
        "$BUILD_DIR/crypto/privmxcrypto_test" \
        "$BUILD_DIR/privfs/privmxprivfs_test"; do
        [[ -x "$bin" ]] && UNIT_BINARIES+=("$bin")
    done
    while IFS= read -r -d '' bin; do
        UNIT_BINARIES+=("$bin")
    done < <(find "$BUILD_DIR/test" -maxdepth 1 -type f -executable -name "test_unit_*" -print0 2>/dev/null | sort -z)

    if [[ ${#UNIT_BINARIES[@]} -eq 0 ]]; then
        echo "No unit test binaries found under '$BUILD_DIR'. Build the project first (see scripts/build.sh)."
        UNIT_FAILED=1
    else
        for bin in "${UNIT_BINARIES[@]}"; do
            echo "--- $bin ---"
            if ! "$bin" ${GTEST_FILTER_ARGS[@]+"${GTEST_FILTER_ARGS[@]}"}; then
                UNIT_FAILED=1
            fi
        done
    fi
    UNIT_TIME=$((SECONDS - UNIT_START))
fi

if [[ "$RUN_E2E" -eq 1 ]]; then
    echo "=== E2E tests ==="
    E2E_START=$SECONDS
    echo "Starting Bridge backend via docker compose..."
    if (cd test/env && docker compose up -d); then
        echo "Waiting for the backend to come up..."
        sleep 15

        python3 test/runner/e2e_runner.py --tests-dir "$BUILD_DIR/test" --dataset-dir "$DATASET_DIR" \
            --docker-image "$BRIDGE_IMAGE" --max-workers $E2E_WORKERS \
            ${GTEST_FILTER_ARGS[@]+"${GTEST_FILTER_ARGS[@]}"}
        E2E_FAILED=$?

        if [[ "$KEEP_BRIDGE" -eq 0 ]]; then
            echo "Tearing down Bridge backend..."
            (cd test/env && docker compose down)
        fi
    else
        echo "Failed to start the Bridge backend via docker compose." >&2
        E2E_FAILED=1
    fi
    E2E_TIME=$((SECONDS - E2E_START))
fi

echo
echo "=== Summary ==="
[[ "$RUN_UNIT" -eq 1 ]] && echo "Unit tests: $([[ "$UNIT_FAILED" -eq 0 ]] && echo PASSED || echo FAILED)  ($(fmt_time $UNIT_TIME))"
[[ "$RUN_E2E" -eq 1 ]] && echo "E2E tests:  $([[ "$E2E_FAILED" -eq 0 ]] && echo PASSED || echo FAILED)  ($(fmt_time $E2E_TIME))"
echo "Total time: $(fmt_time $SECONDS)"

[[ "$UNIT_FAILED" -eq 0 && "$E2E_FAILED" -eq 0 ]]
