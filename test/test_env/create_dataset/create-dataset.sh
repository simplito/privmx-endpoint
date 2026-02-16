#!/bin/bash

set -e

SCRIPT_DIR=$(dirname $(readlink -f "$0"))

if [ -z "$2" ]; then
    echo "Usage: ./create-dataset.sh <privmx-bridge-storage-dir> <privmx-mongo-docker-name> <dataset-name>"
    exit 1
fi
PRIVMX_BRIDGE_STORAGE_DIR=$1
DOCKER_MONGO_NAME=$2

if [ -n "$3" ]; then
    DATASET_NAME=$3
else
    DATASET_NAME=$(date '+%Y%m%d%H%M')
fi
DATASET_DIR=$SCRIPT_DIR/$DATASET_NAME

mkdir -p $DATASET_DIR
cp -r $PRIVMX_BRIDGE_STORAGE_DIR $DATASET_DIR

docker exec $DOCKER_MONGO_NAME bash -c "mkdir mongo_collections"
docker exec $DOCKER_MONGO_NAME bash -c "mongoexport --collection=api_key --db=privmx_localhost --jsonArray --pretty --out=mongo_collections/api_key.json"
docker exec $DOCKER_MONGO_NAME bash -c "mongoexport --collection=api_user --db=privmx_localhost --jsonArray --pretty --out=mongo_collections/api_user.json"
docker exec $DOCKER_MONGO_NAME bash -c "mongoexport --collection=context --db=privmx_localhost --jsonArray --pretty --out=mongo_collections/context.json"
docker exec $DOCKER_MONGO_NAME bash -c "mongoexport --collection=contextUser --db=privmx_localhost --jsonArray --pretty --out=mongo_collections/contextUser.json"
docker exec $DOCKER_MONGO_NAME bash -c "mongoexport --collection=solution --db=privmx_localhost --jsonArray --pretty --out=mongo_collections/solution.json"
# Tread
docker exec $DOCKER_MONGO_NAME bash -c "mongoexport --collection=thread --db=privmx_localhost --jsonArray --pretty --out=mongo_collections/thread.json"
docker exec $DOCKER_MONGO_NAME bash -c "mongoexport --collection=threadMessage --db=privmx_localhost --jsonArray --pretty --out=mongo_collections/threadMessage.json"
# Store
docker exec $DOCKER_MONGO_NAME bash -c "mongoexport --collection=store --db=privmx_localhost --jsonArray --pretty --out=mongo_collections/store.json"
docker exec $DOCKER_MONGO_NAME bash -c "mongoexport --collection=storeFile --db=privmx_localhost --jsonArray --pretty --out=mongo_collections/storeFile.json"
# Kvdb
docker exec $DOCKER_MONGO_NAME bash -c "mongoexport --collection=kvdb --db=privmx_localhost --jsonArray --pretty --out=mongo_collections/kvdb.json"
docker exec $DOCKER_MONGO_NAME bash -c "mongoexport --collection=kvdbEntry --db=privmx_localhost --jsonArray --pretty --out=mongo_collections/kvdbEntry.json"
# Inbox
docker exec $DOCKER_MONGO_NAME bash -c "mongoexport --collection=inbox --db=privmx_localhost --jsonArray --pretty --out=mongo_collections/inbox.json"
docker cp $DOCKER_MONGO_NAME:/mongo_collections $DATASET_DIR

# Migration Status
docker exec $DOCKER_MONGO_NAME bash -c "mongoexport --collection=migration --db=privmx_localhost --jsonArray --pretty --out=migration.json"
docker cp $DOCKER_MONGO_NAME:/migration.json $DATASET_DIR
cp ${SCRIPT_DIR}/ServerData.ini $DATASET_DIR
cp ${SCRIPT_DIR}/ServerData.json $DATASET_DIR

