#!/bin/bash
set -e
SCRIPT_PATH=$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )
source "$SCRIPT_PATH/env.sh"

if [ $# -ne 1 ]; then
    echo "Poszę podać nazwę dokera mongo"
    exit -1
else
    dockerName=$1
fi
# extractiong mongo data - mongoDump
docker exec ${dockerName} mongodump --db privmx_localhost
docker exec ${dockerName} tar -czf dump.tar.gz dump
docker cp ${dockerName}:/dump.tar.gz ./mongo/dump.tar.gz

# # extractiong mongo data - manual
# docker exec ${dockerName} tar -czf data.tar.gz data
# docker cp ${dockerName}:/data.tar.gz ./mongo/data.tar.gz

# # extractiong mongo data from volumen
# tar -czf ./mongo/data.tar.gz -C ./volumes/mongo/ .

#tworznie obrazu
cd mongo
docker build --tag filled_privmx_mongo .
