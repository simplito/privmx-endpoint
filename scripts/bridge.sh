#!/bin/bash
# Usage: ./scripts/bridge.sh [--dataset NAME|DIR] [--index N] [--bridge-image IMAGE] [--keep-backend]

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

DATASET="Dataset"
INDEX=0
BRIDGE_IMAGE="hub.simplito.com/privmx/privmx-bridge:dev"
KEEP_BACKEND=0
MONGO_CONTAINER="privmx_test_mongo"

usage() {
    cat <<EOF
Usage: $0 [options]

  --dataset NAME|DIR     Dataset to seed the Bridge with: a directory, or a name under
                         test/test_env/create_dataset/ (default: $DATASET)
  --index N              Worker index: container privmx_e2e_worker_N on port \$((3001 + N)) (default: $INDEX)
  --bridge-image IMAGE   Bridge docker image (default: $BRIDGE_IMAGE)
  --keep-backend         Leave the compose backend (mongo, janus, coturn) running on exit
  -h, --help             Show this help

Examples:
  $0
  $0 --dataset Dataset_group --index 1
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dataset|--dataset-dir) DATASET="$2"; shift 2 ;;
        --index) INDEX="$2"; shift 2 ;;
        --bridge-image) BRIDGE_IMAGE="$2"; shift 2 ;;
        --keep-backend) KEEP_BACKEND=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

# A dataset is either a path or a name under test/test_env/create_dataset/
DATASET_DIR="$DATASET"
[[ -d "$DATASET_DIR" ]] || DATASET_DIR="test/test_env/create_dataset/$DATASET"
if [[ ! -f "$DATASET_DIR/ServerData.ini" ]]; then
    echo "No dataset with a ServerData.ini at '$DATASET_DIR'." >&2
    echo "Create one with ./scripts/dataset.sh <name>." >&2
    exit 1
fi

mongo_health() { docker inspect -f '{{.State.Health.Status}}' "$MONGO_CONTAINER" 2>/dev/null; }

STARTED_BACKEND=0
cleanup() {
    if [[ "$STARTED_BACKEND" -eq 1 && "$KEEP_BACKEND" -eq 0 ]]; then
        echo "Tearing down the test backend..."
        (cd test && docker compose down)
    fi
}
trap cleanup EXIT

if [[ "$(mongo_health)" != "healthy" ]]; then
    echo "Starting the test backend (mongo, janus, coturn) via docker compose..."
    (cd test && docker compose up -d) || exit 1
    STARTED_BACKEND=1

    printf 'Waiting for MongoDB to become healthy'
    for _ in $(seq 120); do
        [[ "$(mongo_health)" == "healthy" ]] && break
        printf '.'
        sleep 1
    done
    echo
    if [[ "$(mongo_health)" != "healthy" ]]; then
        echo "MongoDB ($MONGO_CONTAINER) did not become healthy in time." >&2
        exit 1
    fi
fi

echo "Dataset: $DATASET_DIR"
python3 test/e2e_runner.py --start-bridge --dataset-dir "$DATASET_DIR" \
    --index "$INDEX" --docker-image "$BRIDGE_IMAGE"
