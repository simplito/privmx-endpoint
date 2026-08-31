#!/bin/bash
set -e
SCRIPT_PATH=$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )
cd $SCRIPT_PATH/..
DIRS=(
    endpoint/core
    endpoint/crypto
    endpoint/android
    endpoint/thread
    endpoint/store
    endpoint/inbox
    endpoint/event
    endpoint/kvdb
    endpoint/stream
    endpoint/search
    endpoint/lock
    endpoint/group
)

FILES=$(find "${DIRS[@]}" \( -name "*.cpp" -o -name "*.hpp" \))

clang-format-20 -i --style=file "$@" $FILES