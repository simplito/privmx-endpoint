#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SESSION_NAME="${SESSION_NAME:-search-bench-multiuser}"
PANE_COUNT="${PANE_COUNT:-2}"
RUN_SCRIPT="$SCRIPT_DIR/run-multiuser.sh"

#if [ ! -x "$RUN_SCRIPT" ]; then
#    echo "Run script is missing or not executable: $RUN_SCRIPT"
#    exit 1
#fi

if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
    tmux kill-session -t "$SESSION_NAME"
fi

tmux new-session -d -s "$SESSION_NAME" "$RUN_SCRIPT"

for ((i = 1; i < PANE_COUNT; i++)); do
    tmux split-window -t "$SESSION_NAME" "$RUN_SCRIPT 2>&1 | tee log-$i-$(date +%s)-$$.txt"
    tmux select-layout -t "$SESSION_NAME" tiled
done

tmux attach -t "$SESSION_NAME"
