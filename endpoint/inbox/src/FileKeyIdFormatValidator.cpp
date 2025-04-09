/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/inbox/FileKeyIdFormatValidator.hpp"
#include "privmx/endpoint/inbox/InboxException.hpp"
using namespace privmx::endpoint::inbox;

void FileKeyIdFormatValidator::assertKeyIdFormat(const std::string& keyId) {
    if (!isKeyIdFormatValid(keyId)) {
        throw IncorrectKeyIdFormatException();
    }
}

bool FileKeyIdFormatValidator::isKeyIdFormatValid(const std::string& keyId) {
    return hasExtendedKeyIdFormat(keyId, "inboxmsg", 3+4+4 ) ? true : hasExtendedKeyIdFormat(keyId, "inboxmsg", 3);
}
