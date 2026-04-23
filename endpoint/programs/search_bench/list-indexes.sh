#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/suites.sh"
source "$SCRIPT_DIR/bridge-env.sh"


PROFILE_ARGS=(--list)

if [ ${#SEARCH_BENCH_SUITES[@]} -eq 0 ]; then
    echo "No suites configured in $SCRIPT_DIR/suites.sh"
    exit 1
fi

cd "$SCRIPT_DIR/../../../build/endpoint/programs/search_bench" || exit
for suite in "${SEARCH_BENCH_SUITES[@]}"; do
    echo "Running suite: $suite"
    ./search_bench "${PROFILE_ARGS[@]}" "$suite" "$PRIV_KEY" "$SOLUTION_ID" "$BRIDGE_URL" "$CONTEXT_ID" "$RFC_DIR" "$MESSAGES_DIR"
done
