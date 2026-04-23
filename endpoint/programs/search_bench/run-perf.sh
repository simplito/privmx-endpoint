#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/suites.sh"
#source "$SCRIPT_DIR/../../../build/build/Debug/generators/conanrun.sh"
source "$SCRIPT_DIR/bridge-env.sh"
ORIGINAL_PERF_EVENT_PARANOID="$(cat /proc/sys/kernel/perf_event_paranoid)"
restore_perf_permissions() {
    echo "$ORIGINAL_PERF_EVENT_PARANOID" > /proc/sys/kernel/perf_event_paranoid
}
trap restore_perf_permissions EXIT

echo "0" > /proc/sys/kernel/perf_event_paranoid

PROFILE_OUT_DIR="/tmp/search-bench-profiles"
PROFILE_ARGS=(--profile perf --profile-out "$PROFILE_OUT_DIR")

if [ ${#SEARCH_BENCH_SUITES[@]} -eq 0 ]; then
    echo "No suites configured in $SCRIPT_DIR/suites.sh"
    exit 1
fi

mkdir -p "$PROFILE_OUT_DIR"

cd "$SCRIPT_DIR/../../../build/endpoint/programs/search_bench" || exit
for suite_entry in "${SEARCH_BENCH_SUITES[@]}"; do
    read -r -a suite_args <<< "$suite_entry"
    if [ ${#suite_args[@]} -eq 0 ]; then
        continue
    fi
    suite_name="${suite_args[0]}"
    echo "Profiling suite: $suite_name"
    ./search_bench "${PROFILE_ARGS[@]}" "${suite_args[@]}" "$PRIV_KEY" "$SOLUTION_ID" "$BRIDGE_URL" "$CONTEXT_ID" "$RFC_DIR" "$MESSAGES_DIR"
    perf script -i "$PROFILE_OUT_DIR/$suite_name.perf.data" | "$SCRIPT_DIR/stackcollapse-perf.pl" | "$SCRIPT_DIR/flamegraph.pl" > "$PROFILE_OUT_DIR/$suite_name.svg"
done
