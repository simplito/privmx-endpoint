#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/suites.sh"
source "$SCRIPT_DIR/bridge-env.sh"
#source "$SCRIPT_DIR/../../../build/build/Debug/generators/conanrun.sh"
PROFILE_ARGS=()
# PROFILE_ARGS=(--profile perf --profile-out /tmp/search-bench-profiles)

if [ ${#SEARCH_BENCH_SUITES[@]} -eq 0 ]; then
    echo "No suites configured in $SCRIPT_DIR/suites.sh"
    exit 1
fi

cd "$SCRIPT_DIR/../../../build/endpoint/programs/search_bench" || exit
for suite_entry in "${SEARCH_BENCH_SUITES[@]}"; do
    read -r -a suite_args <<< "$suite_entry"
    if [ ${#suite_args[@]} -eq 0 ]; then
        continue
    fi
    echo "Running suite: ${suite_args[0]}"
    ./search_bench "${PROFILE_ARGS[@]}" "${suite_args[@]}" "$PRIV_KEY" "$SOLUTION_ID" "$BRIDGE_URL" "$CONTEXT_ID" "$RFC_DIR" "$MESSAGES_DIR"
done
