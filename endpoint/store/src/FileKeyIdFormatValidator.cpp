/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/store/FileKeyIdFormatValidator.hpp"
#include "privmx/endpoint/store/StoreException.hpp"
using namespace privmx::endpoint::store;

void FileKeyIdFormatValidator::assertKeyIdFormat(const std::string& keyId) {
    if (!isKeyIdFormatValid(keyId)) {
        throw IncorrectKeyIdFormatException();
    }
}

bool FileKeyIdFormatValidator::isKeyIdFormatValid(const std::string& keyId) {
    return hasDefaultKeyIdFormat(keyId);
}
