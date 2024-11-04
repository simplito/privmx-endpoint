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

function server_curl {
    local JSON=$(curl -s -X POST $URL --data-binary "{\"jsonrpc\": \"2.0\", \"id\": 1, \"method\": \"$1\", \"params\": $2}" -H "Authorization: Basic $AUTH")
    sleep 0.5
    echo "$JSON"
}

echo "Creating api key"
apiKey=$(docker exec ${dockerName} pmxbridge_createapikey)
echo "$apiKey" > api_key.ini
source api_key.ini
AUTH_DATA="$API_KEY_ID:$API_KEY_SECRET"
AUTH=$(echo -n "$AUTH_DATA" | base64 -w0)
URL=http://localhost:${DOCKER_PORT}/api

user_1_privKey=Kx9ftJtfa4Af941f9jYR44dKxv9uWMxkJBk3XgdSYy6M5i6zcXxS
user_1_pubKey=6GdpXA9ro6hDabKKFsnuq4EJ1NYNLqsnLzTLCAyL55FMSk8xSM
user_1_id=user_1

user_2_privKey=L2KX5JrHkGBzGvMJ41bDhwgwN1JpqGKYk8feJEyri8bdqkqd84kt
user_2_pubKey=86uPnTCSQ2WzEoM1EYGWt2dEc1jmR51HrVw5wTydxiDyuHDMty
user_2_id=user_2


echo "Creating solution"
method=solution/createSolution
solution_1_JSON=$(server_curl "$method" "{\"name\": \"Main\"}")
solutionId=$(echo $solution_1_JSON | jq -r '.result.solutionId')
echo "Creating Contexts"
method='context/createContext'
echo "Creating Context_1"
contextData_1_JSON=$(server_curl "$method" "{\"name\": \"MainContext\", \"solution\": \"${solutionId}\", \"description\": \"Context nr 1\", \"scope\": \"private\"}")
contextId_1=$(echo $contextData_1_JSON | jq -r ".result.contextId")
echo "Creating Context_2"
contextData_2_JSON=$(server_curl "$method" "{\"name\": \"SecondaryContext\", \"solution\": \"${solutionId}\", \"description\": \"Context nr 2\", \"scope\": \"private\"}")
contextId_2=$(echo $contextData_2_JSON | jq -r ".result.contextId")

echo "Adding users to Contexts"
method='context/addUserToContext'
echo "Adding user_1 to Context_1"
addUserToContextData_1=$(server_curl "$method" "{\"contextId\": \"${contextId_1}\", \"userId\": \"${user_1_id}\", \"userPubKey\": \"${user_1_pubKey}\"}")
echo "Adding user_2 to Context_1"
addUserToContextData_1=$(server_curl "$method" "{\"contextId\": \"${contextId_1}\", \"userId\": \"${user_2_id}\", \"userPubKey\": \"${user_2_pubKey}\"}")
echo "Adding user_1 to Context_2"
addUserToContextData_1=$(server_curl "$method" "{\"contextId\": \"${contextId_2}\", \"userId\": \"${user_1_id}\", \"userPubKey\": \"${user_1_pubKey}\"}")
echo "Adding user_2 to Context_2"
addUserToContextData_1=$(server_curl "$method" "{\"contextId\": \"${contextId_2}\", \"userId\": \"${user_2_id}\", \"userPubKey\": \"${user_2_pubKey}\"}")
cat << EOF > ServerData.ini
[Login]
user_1_privKey = $user_1_privKey
user_1_pubKey = $user_1_pubKey
user_1_id = $user_1_id
user_2_privKey = $user_2_privKey
user_2_pubKey = $user_2_pubKey
user_2_id = $user_2_id
solutionId = $solutionId
instanceUrl = http://localhost/
[Context_1]
contextId = $contextId_1
[Context_2]
contextId = $contextId_2
EOF
