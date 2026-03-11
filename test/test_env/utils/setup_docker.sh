#!/bin/bash
SCRIPT_PATH=$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )
BUILD_PATH="${SCRIPT_PATH}/../../../build/test"

{

    "${SCRIPT_PATH}/clean_up_volumes.sh"
    echo Creating Docker
    # docker compose -f "${SCRIPT_PATH}/empty_server_and_mongo.yml" pull
    docker compose -f "${SCRIPT_PATH}/empty_server_and_mongo.yml" up -d --wait
} || {
    echo Failed to Create Docker
    exit 1
}
{
    echo Filling Docker with initial data
    "${SCRIPT_PATH}/DockerSetupInit.sh" empty_server_and_mongo-teamserver-1
    "${BUILD_PATH}/test_env_DockerSetupData"
} || {
    echo Failed to fill docker
    "${SCRIPT_PATH}/stop_docker.sh"
    exit 1
}
