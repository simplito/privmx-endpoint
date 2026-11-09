#!/bin/bash
#
# Usage: ./scripts/generate_test_dataset.sh [--build-dir DIR] [--bridge-image IMAGE] [--output NAME]
#
# Generates the e2e dataset (test/env/datasets/<NAME>) that run_tests.sh seeds the Bridge with. Run it once before
# the e2e tests, with the same build and Bridge image as the tests. Needs Docker and ports 12345/12346.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

BUILD_DIR="build"
BRIDGE_IMAGE="hub.simplito.com/privmx/privmx-bridge:dev"
OUTPUT="Dataset"

usage() {
    cat <<USAGE
Usage: $0 [options]

  --build-dir DIR        Build directory holding test/test_env_DockerSetupData (default: $BUILD_DIR)
  --bridge-image IMAGE   Bridge image to generate the dataset with (default: $BRIDGE_IMAGE)
  --output NAME          Dataset name under test/env/datasets/ (default: $OUTPUT)
  -h, --help             Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --build-dir) BUILD_DIR="$2"; shift 2 ;;
        --bridge-image) BRIDGE_IMAGE="$2"; shift 2 ;;
        --output) OUTPUT="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

if [[ ! -x "$BUILD_DIR/test/test_env_DockerSetupData" ]]; then
    echo "No test_env_DockerSetupData in '$BUILD_DIR/test'. Build the project first (see scripts/build.sh)." >&2
    exit 1
fi
TESTS_DIR="$(cd "$BUILD_DIR" && pwd)/test"

IMAGE_REPO="$BRIDGE_IMAGE"
IMAGE_TAG="latest"
if [[ "${BRIDGE_IMAGE##*/}" == *:* ]]; then
    IMAGE_REPO="${BRIDGE_IMAGE%:*}"
    IMAGE_TAG="${BRIDGE_IMAGE##*:}"
fi

DATASET_TESTS_DIR="$TESTS_DIR" ./scripts/dataset.sh "$OUTPUT" -i "$IMAGE_REPO" -v "$IMAGE_TAG"

# main.sh exits 0 even when generation fails, so check the result.
if [[ ! -f "test/env/datasets/$OUTPUT/ServerData.ini" ]]; then
    echo "Dataset generation failed: no test/env/datasets/$OUTPUT/ServerData.ini." >&2
    exit 1
fi
echo "Dataset ready: test/env/datasets/$OUTPUT"
