/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/core/TimestampValidator.hpp"

using namespace privmx::endpoint::core;

bool TimestampValidator::validate(int64_t clinetTimestamp, int64_t serverTimestamp) {
    return abs(serverTimestamp - clinetTimestamp) < TIMESTAMP_ALLOWED_DELTA;
}