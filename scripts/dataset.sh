#!/bin/bash
#
# Generates a PrivMX Bridge test dataset: spins up an empty Bridge + Mongo, seeds it via the
# test_env_DockerSetupData binary, exports the result into test/test_env/create_dataset/<name>, and
# tears the containers down again. Thin wrapper around test/test_env/create_dataset/main.sh.
#
# Usage:
#   ./scripts/dataset.sh                  Create a new dataset named Dataset_<timestamp>
#   ./scripts/dataset.sh <name>           Create a new dataset named <name>, or refresh it in place
#                                         if <name> already exists (e.g. Dataset, Dataset_group)
#
# Any extra options (-i/--docker-image, -v/--docker-version, -p/--docker-port) are forwarded to main.sh.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CREATE_DATASET_DIR="$SCRIPT_DIR/../test/test_env/create_dataset"

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    cat <<EOF
Usage: $0 [name] [main.sh options...]

  name    Dataset directory name under test/test_env/create_dataset/. An existing name is
          refreshed in place (update); omit it to create a fresh Dataset_<timestamp>.

Remaining options are forwarded to main.sh: -i/--docker-image, -v/--docker-version, -p/--docker-port.
EOF
    exit 0
fi

NAME=""
if [[ $# -gt 0 && "$1" != -* ]]; then
    NAME="$1"
    shift
fi

cd "$CREATE_DATASET_DIR"

if [[ -n "$NAME" ]]; then
    if [[ -d "$NAME" ]]; then
        echo "Updating existing dataset '$NAME' in place..."
    else
        echo "Creating new dataset '$NAME'..."
    fi
    exec ./main.sh --output "$NAME" "$@"
fi

echo "Creating new dataset..."
exec ./main.sh "$@"
