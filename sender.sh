#!/bin/bash
bridgeUrl="http://localhost:3000"
solutionId="2724131d-6536-464a-94ff-8faae7bbe6b7"
contextId="5856dae6-b6b1-46d0-8944-ee9d39621907"

privateKey="L2BzxLU5owyT9pcvj9vKeCP4i7GvubVry9LWCqUK91P6tppoiYVL"
publicKey="7dSdso7aCsTFTnzbE4iRxUhQir387BpzNwXY7crYk7jeto6zw3"
username="43f097dd46325635"

source ./build/build/Debug/generators/conanrun.sh
cd ./build/endpoint/programs/stream_testing
./streams_program_3_sender $privateKey $solutionId $bridgeUrl $contextId "not_used"
