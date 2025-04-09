/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/inbox/MessageKeyIdFormatValidator.hpp"
#include "privmx/endpoint/inbox/InboxException.hpp"
#include <privmx/utils/Utils.hpp>
using namespace privmx::endpoint::inbox;

void MessageKeyIdFormatValidator::assertKeyIdFormat(const std::string& keyId) {
    if (!isKeyIdFormatValid(keyId)) {
        throw IncorrectKeyIdFormatException();
    }
}

bool MessageKeyIdFormatValidator::isKeyIdFormatValid(const std::string& keyId) {
    return hasExtendedKeyIdFormat(keyId, "inbox", 1+4 ) ? true : hasExtendedKeyIdFormat(keyId, "inbox", 1);
}
