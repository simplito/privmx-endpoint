#!/bin/bash
SCRIPT_PATH=$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )
echo Cleaning all volumes files
docker run --rm -v "$SCRIPT_PATH/volumes:/volumes" busybox rm -rf /volumes/mongo /volumes/bridge 