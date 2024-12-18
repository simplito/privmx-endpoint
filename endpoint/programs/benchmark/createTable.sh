# /bin/bash
set -e
SCRIPT_PATH=$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )

WORKSPACE_PATH="${SCRIPT_PATH}/../../.."
BUILD_PATH="${WORKSPACE_PATH}/build/endpoint/programs/benchmark"
source "$SCRIPT_PATH/env.sh"

function run_benchmark {
    DOCKER_LOCATION=$(curl -s http://${INSTANCE_SERVER}/getInstance | jq .instance.instanceUrl)
    #removing ""
    DOCKER_LOCATION="${DOCKER_LOCATION#?}"
    DOCKER_LOCATION="${DOCKER_LOCATION%?}"
    export PLATFORM_URL="${DOCKER_LOCATION}"
    ${BUILD_PATH}/privmxBenchmark Count 100 $1 $2
    curl -s http://${INSTANCE_SERVER}/releaseInstance?url=$DOCKER_LOCATION | jq .result
}

echo "Thread getMessage"
run_benchmark thread 131072

echo "Thread getMessage 1KB"
run_benchmark thread 131073

echo "Thread getMessage 4KB"
run_benchmark thread 131074

echo "Thread sendMessage"
run_benchmark thread 65536

echo "Thread sendMessage 1KB"
run_benchmark thread 65541

echo "Thread sendMessage 4KB"
run_benchmark thread 65542

echo "Store getFile"
run_benchmark store 131072

echo "Store getFile 1MB"
run_benchmark store 131073

echo "Store getFile 8MB"
run_benchmark store 131074

echo "Store create file"
run_benchmark store 65536

echo "Store create file 1MB"
run_benchmark store 65541

echo "Store create file 8MB"
run_benchmark store 65542

echo "Inbox readEntry no files"
run_benchmark inbox 131072

echo "Inbox readEntry 5 files"
run_benchmark inbox 131073

echo "Inbox readEntry 5 files 1MB"
run_benchmark inbox 131074

echo "Inbox create entry no files"
run_benchmark inbox 65536

echo "Inbox create entry 5 files"
run_benchmark inbox 65541

echo "Inbox create entry 5 files 1MB"
run_benchmark inbox 65542




# create Table