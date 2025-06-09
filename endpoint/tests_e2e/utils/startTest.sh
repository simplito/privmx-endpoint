#!/bin/bash
SCRIPT_PATH=$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )
source "$SCRIPT_PATH/env.sh"
if [[ ! -f "$INI_FILE_PATH" ]]; then
    echo "$INI_FILE_PATH not exists."
    exit -1
fi
if [ $# -ne 1 ]; then
    echo "Poszę podać nazwę testu"
    echo "lista testów: CoreTest, CoreModuleEventsTest, ThreadTest, ThreadModuleEventsTest, StoreTest, StoreModuleEventsTest, InboxTest, InboxModuleEventsTest, EventsTest, CryptoTest, UtilsTest"
    exit -1
else
    first_arg="$1"
    shift
fi


if [ "${first_arg}" == "CoreTest" ]; then
    ./privmxplatform_test_e2e_CoreTest $@
elif [ "${first_arg}" == "CoreModuleEventsTest" ]; then
    ./privmxplatform_test_e2e_CoreModuleEventsTest $@
elif [ "${first_arg}" == "ThreadTest" ]; then
    ./privmxplatform_test_e2e_ThreadTest $@
elif [ "${first_arg}" == "ThreadModuleEventsTest" ]; then
    ./privmxplatform_test_e2e_ThreadModuleEventsTest $@
elif [ "${first_arg}" == "StoreTest" ]; then
    ./privmxplatform_test_e2e_StoreTest $@
elif [ "${first_arg}" == "StoreModuleEventsTest" ]; then
    ./privmxplatform_test_e2e_StoreModuleEventsTest $@
elif [ "${first_arg}" == "InboxTest" ]; then
    ./privmxplatform_test_e2e_InboxTest $@
elif [ "${first_arg}" == "InboxModuleEventsTest" ]; then
    ./privmxplatform_test_e2e_InboxModuleEventsTest $@
elif [ "${first_arg}" == "KvdbTest" ]; then
    ./privmxplatform_test_e2e_KvdbTest $@
elif [ "${first_arg}" == "KvdbModuleEventsTest" ]; then
    ./privmxplatform_test_e2e_KvdbModuleEventsTest $@
elif [ "${first_arg}" == "EventsTest" ]; then
    ./privmxplatform_test_e2e_EventsTest $@
elif [ "${first_arg}" == "CryptoTest" ]; then
    ./privmxplatform_test_e2e_CryptoTest $@
elif [ "${first_arg}" == "UtilsTest" ]; then
    ./privmxplatform_test_e2e_UtilsTest $@
elif [ "${first_arg}" == "All" ]; then
    set -e
    ./privmxplatform_test_e2e_CoreTest $@
    ./privmxplatform_test_e2e_CoreModuleEventsTest $@
    ./privmxplatform_test_e2e_ThreadTest $@
    ./privmxplatform_test_e2e_ThreadModuleEventsTest $@
    ./privmxplatform_test_e2e_StoreTest $@
    ./privmxplatform_test_e2e_StoreModuleEventsTest $@
    ./privmxplatform_test_e2e_InboxTest $@
    ./privmxplatform_test_e2e_InboxModuleEventsTest $@
    ./privmxplatform_test_e2e_KvdbTest $@
    ./privmxplatform_test_e2e_KvdbModuleEventsTest $@
    ./privmxplatform_test_e2e_EventsTest $@
    ./privmxplatform_test_e2e_CryptoTest $@
    ./privmxplatform_test_e2e_UtilsTest $@
else
    echo "unknown test"
fi

