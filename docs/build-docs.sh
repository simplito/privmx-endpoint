#!/bin/bash
set -e

SCRIPT_PATH=$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )

VERSION=${1:-${PRIVMX_ENDPOINT_VERSION:-""}}

echo "Version: $VERSION"

cd "$SCRIPT_PATH"

export PRIVMX_ENDPOINT_VERSION="$VERSION"
doxygen Doxyfile
