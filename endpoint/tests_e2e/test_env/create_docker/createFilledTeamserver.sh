#!/bin/bash
set -e
SCRIPT_PATH=$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )
source "$SCRIPT_PATH/env.sh"

if [ $# -ne 1 ]; then
    echo "Poszę podać nazwę dokera teamserver"
    exit -1
else
    dockerName=$1
fi
#extractiong mongo data
docker exec ${dockerName} tar -czf /storage.tar.gz /work/privmx-bridge/storage
docker cp ${dockerName}:/storage.tar.gz ./teamserver/storage.tar.gz
#tworznie obrazu
cd teamserver
docker build --build-arg TEAMSERVER_VERSION=${TEAMSERVER_VERSION} --tag filled_privmx_teamserver .

