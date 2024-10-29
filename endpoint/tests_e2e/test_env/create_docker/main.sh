#!/bin/bash
SCRIPT_PATH=$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )
UTIL_PATH="${SCRIPT_PATH}/../../utils"
BUILD_PATH="${SCRIPT_PATH}/../../../../build/endpoint/tests_e2e"
docker compose pull

source "${SCRIPT_PATH}/env.sh"

{
    echo Creating Docker
    docker compose -f "${SCRIPT_PATH}/empty_server_and_mongo.yml" pull
    docker compose -f "${SCRIPT_PATH}/empty_server_and_mongo.yml" up -d --wait
} || {
    exit
}
{
    echo Creating inital data
    "${SCRIPT_PATH}/DockerSetupInit.sh" empty_server_and_mongo-teamserver-1
    "${BUILD_PATH}/privmxplatform_test_e2e_DockerSetupData"
} || {
    echo Failed to fill docker
    docker compose -f "${SCRIPT_PATH}/empty_server_and_mongo.yml" kill
    docker compose -f "${SCRIPT_PATH}/empty_server_and_mongo.yml" down
    exit
}

{
    echo Creating FilledDockers
    sleep 5s
    "${SCRIPT_PATH}/createFilledTeamserver.sh" empty_server_and_mongo-teamserver-1
    "${SCRIPT_PATH}/createFilledMongo.sh" empty_server_and_mongo-mongodb-1
} || {
    echo Failed to create FilledDockers
}

echo Killing Docker
# sleep 5s
docker compose -f "${SCRIPT_PATH}/empty_server_and_mongo.yml" kill
docker compose -f "${SCRIPT_PATH}/empty_server_and_mongo.yml" down
# rm -r "${SCRIPT_PATH}/volumes"
