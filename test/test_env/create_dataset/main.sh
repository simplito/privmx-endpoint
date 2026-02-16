#!/bin/bash
SCRIPT_PATH=$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )
UTILS_PATH="${SCRIPT_PATH}/../utils"
source "${UTILS_PATH}/default_values.sh"
cd $SCRIPT_PATH

outputPath=Dataset_$(date '+%Y-%m-%d_%H-%M')

while test $# -gt 0; do
  case "$1" in
    -h|--help)
      echo "creator of privmx-bridge snapshots for tests-api-provider "
      echo " "
      echo "options:"
      echo "-h, --help                show brief help"
      echo "-i, --docker-image            overwrite DOCKER_BRIDGE_IMAGE current value \"${DOCKER_BRIDGE_IMAGE}\""
      echo "-v ,--docker-version          overwrite DOCKER_BRIDGE_VERSION current value \"${DOCKER_BRIDGE_VERSION}\""
      echo "-p, --docker-port             overwrite DOCKER_BRIDGE_PORT current value \"${DOCKER_BRIDGE_PORT}\""
      echo "-o, --output                  overwrite default value \"Dataset_<date '+%Y-%m-%d_%H-%M'>\""
      exit 0
      ;;
    -i|--docker-image)
      shift
      if test $# -gt 0; then
        DOCKER_BRIDGE_IMAGE=$1
      else
        echo "no DOCKER_BRIDGE_IMAGE specified"
        exit 1
      fi
      shift
      ;;
    -v|--docker-version)
      shift
      if test $# -gt 0; then
        DOCKER_BRIDGE_VERSION=$1
      else
        echo "no DOCKER_BRIDGE_VERSION specified"
        exit 1
      fi
      shift
      ;;
    -p|--docker-port)
      shift
      if test $# -gt 0; then
        DOCKER_BRIDGE_PORT=$1
      else
        echo "no DOCKER_BRIDGE_PORT specified"
        exit 1
      fi
      shift
      ;;
    -o|--output)
      shift
      if test $# -gt 0; then
        outputPath=$1
      else
        echo "no output specified"
        exit 1
      fi
      shift
      ;;
    *)
      break
      ;;
  esac
done

set -e

"${UTILS_PATH}/setup_docker.sh"
set +e
echo Creating dataset
sleep 5s
{
    "${SCRIPT_PATH}/create-dataset.sh" "${UTILS_PATH}/volumes/bridge/storage" empty_server_and_mongo-mongodb-1 "${outputPath}"
} || {
    echo Failed to create Snapshot
}
"${UTILS_PATH}/stop_docker.sh"