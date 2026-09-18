#!/bin/bash
SCRIPT_PATH=$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )

echo Stopping Docker
docker compose -f "${SCRIPT_PATH}/empty_server_and_mongo.yml" kill
docker compose -f "${SCRIPT_PATH}/empty_server_and_mongo.yml" down
