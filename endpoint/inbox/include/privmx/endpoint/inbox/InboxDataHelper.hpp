/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_INBOX_INBOXDATAHELPER_HPP_
#define _PRIVMXLIB_ENDPOINT_INBOX_INBOXDATAHELPER_HPP_

#include <string>
#include "privmx/utils/Utils.hpp"
#include "privmx/endpoint/inbox/ServerTypes.hpp"
#include "privmx/endpoint/inbox/Types.hpp"
#include "privmx/endpoint/core/CoreTypes.hpp"
#include <Poco/JSON/Array.h>
#include <Poco/JSON/Object.h>
#include <privmx/crypto/Crypto.hpp>
#include "privmx/endpoint/inbox/Factory.hpp"

namespace privmx {
namespace endpoint {
namespace inbox {

class InboxDataHelper {
public:
    static std::string serializeEncKey(const privmx::endpoint::core::EncKey& key);
    static privmx::endpoint::core::EncKey deserializeEncKey(const std::string& serializedKey);
    static std::string getRandomName();

    static server::FileConfig fileConfigToTypedObject(const FilesConfig& fileConfig);
    static FilesConfig fileConfigFromTypedObject(const server::FileConfig& fileConfig);

    static privmx::utils::List<std::string> mapUsers(const std::vector<core::UserWithPubKey>& users);
};


}
}
}

#endif // _PRIVMXLIB_ENDPOINT_INBOX_INBOXDATAHELPER_HPP_
