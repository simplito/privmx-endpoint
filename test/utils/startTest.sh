#!/bin/bash
SCRIPT_PATH=$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )
source "$SCRIPT_PATH/env.sh"
if [[ ! -f "$INI_FILE_PATH" ]]; then
    echo "$INI_FILE_PATH not exists."
    exit -1
fi
if [ $# -ne 1 ]; then
    echo "Poszę podać nazwę testu"
    echo "lista testów: CoreTest, CoreModuleEventsTest, ThreadTest, ThreadModuleEventsTest, StoreTest, StoreModuleEventsTest, InboxTest, InboxModuleEventsTest, KvdbModule, KvdbModuleEventsTest, EventsTest, CryptoTest, UtilsTest"
    exit -1
else
    first_arg="$1"
    shift
fi


if [ "${first_arg}" == "CoreTest" ]; then
    ./test_e2e_CoreTest $@
elif [ "${first_arg}" == "CoreModuleEventsTest" ]; then
    ./test_e2e_CoreModuleEventsTest $@
elif [ "${first_arg}" == "ThreadTest" ]; then
    ./test_e2e_ThreadTest $@
elif [ "${first_arg}" == "ThreadModuleEventsTest" ]; then
    ./test_e2e_ThreadModuleEventsTest $@
elif [ "${first_arg}" == "StoreTest" ]; then
    ./test_e2e_StoreTest $@
elif [ "${first_arg}" == "StoreModuleEventsTest" ]; then
    ./test_e2e_StoreModuleEventsTest $@
elif [ "${first_arg}" == "InboxTest" ]; then
    ./test_e2e_InboxTest $@
elif [ "${first_arg}" == "InboxModuleEventsTest" ]; then
    ./test_e2e_InboxModuleEventsTest $@
elif [ "${first_arg}" == "KvdbTest" ]; then
    ./test_e2e_KvdbTest $@
elif [ "${first_arg}" == "KvdbModuleEventsTest" ]; then
    ./test_e2e_KvdbModuleEventsTest $@
elif [ "${first_arg}" == "EventsTest" ]; then
    ./test_e2e_EventsTest $@
elif [ "${first_arg}" == "CryptoTest" ]; then
    ./test_e2e_CryptoTest $@
elif [ "${first_arg}" == "UtilsTest" ]; then
    ./test_e2e_UtilsTest $@
elif [ "${first_arg}" == "All" ]; then
    set -e
    ./test_e2e_CoreTest $@
    ./test_e2e_CoreModuleEventsTest $@
    ./test_e2e_ThreadTest $@
    ./test_e2e_ThreadModuleEventsTest $@
    ./test_e2e_StoreTest $@
    ./test_e2e_StoreModuleEventsTest $@
    ./test_e2e_InboxTest $@
    ./test_e2e_InboxModuleEventsTest $@
    ./test_e2e_KvdbTest $@
    ./test_e2e_KvdbModuleEventsTest $@
    ./test_e2e_EventsTest $@
    ./test_e2e_CryptoTest $@
    ./test_e2e_UtilsTest $@
else
    echo "unknown test"
fi

