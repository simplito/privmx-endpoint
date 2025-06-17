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

#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/ServerTypes.hpp>
#include <privmx/endpoint/core/Types.hpp>
#include <privmx/endpoint/core/UserVerifierInterface.hpp>
#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/EciesEncryptor.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include "privmx/endpoint/event/ServerTypes.hpp"
#include "privmx/endpoint/event/EventTypes.hpp"

namespace privmx {
namespace endpoint {
namespace event {

class EventKeyProvider {
public:
    EventKeyProvider(const privmx::crypto::PrivateKey& key);
    std::string generateKey();
    DecryptedEventEncKeyV1 decryptKey(const std::string& encryptedKey, const privmx::crypto::PublicKey& authorPubKey);
    utils::List<server::UserKey> prepareKeysList(
        const std::vector<core::UserWithPubKey>& users, 
        const std::string& key
    );
private:
    privmx::crypto::PrivateKey _key;
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_EVENT_EVENTKEYPROVIDER_HPP_
