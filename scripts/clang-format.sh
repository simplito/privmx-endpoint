#!/bin/bash
set -e
SCRIPT_PATH=$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )
cd $SCRIPT_PATH/..

# clang-format changed its BlockIndent output in 20.1.4, so the version is pinned instead of
# taking whatever the distro ships. Override with CLANG_FORMAT=/path/to/clang-format.
CLANG_FORMAT_VERSION="20.1.8"

find_clang_format() {
    for candidate in "$CLANG_FORMAT" clang-format clang-format-20; do
        [ -n "$candidate" ] || continue
        command -v "$candidate" >/dev/null 2>&1 || continue
        if "$candidate" --version | grep -qF "clang-format version $CLANG_FORMAT_VERSION"; then
            echo "$candidate"
            return 0
        fi
    done
    return 1
}

if ! BIN=$(find_clang_format); then
    echo "clang-format $CLANG_FORMAT_VERSION not found." >&2
    echo "Install it with: pipx install clang-format==$CLANG_FORMAT_VERSION" >&2
    exit 1
fi

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

"$BIN" -i --style=file "$@" $FILES
