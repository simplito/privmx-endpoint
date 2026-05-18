#!/bin/bash
set -e

SCRIPT_PATH=$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )

cd "$SCRIPT_PATH"

PRIVMX_ENDPOINT_VERSION=$(git describe --tags --always) "$SCRIPT_PATH/build-docs.sh"
