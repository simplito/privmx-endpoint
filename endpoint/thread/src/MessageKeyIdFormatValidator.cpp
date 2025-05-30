/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/thread/MessageKeyIdFormatValidator.hpp"
#include "privmx/endpoint/thread/ThreadException.hpp"
using namespace privmx::endpoint::thread;

void MessageKeyIdFormatValidator::assertKeyIdFormat(const std::string& keyId) {
    if (!isKeyIdFormatValid(keyId)) {
        throw IncorrectKeyIdFormatException();
    }
}

bool MessageKeyIdFormatValidator::isKeyIdFormatValid(const std::string& keyId) {
    return hasDefaultKeyIdFormat(keyId);
}
