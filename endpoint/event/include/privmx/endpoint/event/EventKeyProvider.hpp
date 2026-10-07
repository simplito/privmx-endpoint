/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_EVENT_EVENTKEYPROVIDER_HPP_
#define _PRIVMXLIB_ENDPOINT_EVENT_EVENTKEYPROVIDER_HPP_

#include "privmx/endpoint/event/EventTypes.hpp"
#include "privmx/endpoint/event/ServerTypes.hpp"
#include <privmx/crypto/Crypto.hpp>
#include <privmx/endpoint/core/crypto/Ecies.hpp>
#include <privmx/endpoint/core/crypto/PrivateKey.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/ServerTypes.hpp>
#include <privmx/endpoint/core/Types.hpp>
#include <privmx/endpoint/core/UserVerifierInterface.hpp>

namespace privmx {
namespace endpoint {
namespace event {

class EventKeyProvider {
public:
    EventKeyProvider(const core::PrivateKey& key);
    std::string generateKey();
    DecryptedEventEncKeyV1 decryptKey(const std::string& encryptedKey, const core::PublicKey& authorPubKey);
    std::vector<server::UserKey> prepareKeysList(
        const std::vector<core::UserWithPubKey>& users,
        const std::string& key
    );

private:
    core::PrivateKey _key;
};

} // namespace event
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_EVENT_EVENTKEYPROVIDER_HPP_
