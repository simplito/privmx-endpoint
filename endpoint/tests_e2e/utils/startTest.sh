#!/bin/bash
SCRIPT_PATH=$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )
source "$SCRIPT_PATH/env.sh"
if [[ ! -f "$INI_FILE_PATH" ]]; then
    echo "$INI_FILE_PATH not exists."
    exit -1
fi
if [ $# -ne 1 ]; then
    echo "Poszę podać nazwę testu"
    echo "lista testów: CoreTest, ThreadTest, StoreTest, InboxTest, EventsTest"
    exit -1
else
    first_arg="$1"
    shift
fi


if [ "${first_arg}" == "CoreTest" ]; then
    ./privmxplatform_test_e2e_CoreTest $@
elif [ "${first_arg}" == "ThreadTest" ]; then
    ./privmxplatform_test_e2e_ThreadTest $@
elif [ "${first_arg}" == "StoreTest" ]; then
    ./privmxplatform_test_e2e_StoreTest $@
elif [ "${first_arg}" == "InboxTest" ]; then
    ./privmxplatform_test_e2e_InboxTest $@
elif [ "${first_arg}" == "EventsTest" ]; then
    ./privmxplatform_test_e2e_EventsTest $@
else
    echo "unknown test"
fi

