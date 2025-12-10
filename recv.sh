#!/bin/bash
bridgeUrl="http://localhost:3000"
solutionId="2724131d-6536-464a-94ff-8faae7bbe6b7"
contextId="5856dae6-b6b1-46d0-8944-ee9d39621907"

privateKey="L1HDrDJaFLX3VYyUgDVNBzuVwEdbWpFSnhSWntM2z5BWSdNLueBi"
publicKey="5wqKtZabk7fYfQwug4uuY6fi6x3HjXhDoWPwPLYNvY8BYyex2e"
username="349a3a7426950e44"

source ./build/build/Debug/generators/conanrun.sh
cd ./build/endpoint/programs/stream_testing
./streams_program_3_reciver $privateKey $solutionId $bridgeUrl $contextId "not_used"
