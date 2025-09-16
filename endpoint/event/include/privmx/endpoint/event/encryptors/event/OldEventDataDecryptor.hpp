/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/
#ifndef _PRIVMXLIB_ENDPOINT_EVENT_OLDEVENTDATADECRYPTOR_HPP_
#define _PRIVMXLIB_ENDPOINT_EVENT_OLDEVENTDATADECRYPTOR_HPP_

#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/encryptors/DataEncryptorV4.hpp>
#include <privmx/endpoint/core/Types.hpp>
#include <privmx/crypto/ecc/PublicKey.hpp>
#include "privmx/endpoint/event/EventTypes.hpp"

namespace privmx {
namespace endpoint {
namespace event {

class OldEventDataDecryptor {
public:
    DecryptedContextEventDataV1 decryptV1(const Poco::Dynamic::Var& data, const crypto::PublicKey& authorPublicKey, const std::string& encryptionKey, const crypto::PrivateKey& userPrivateKey);
private:
    core::DataEncryptorV4 _dataEncryptor;
};

}  // namespace event
}  // namespace endpoint
}  // namespace privmx

#endif  //_PRIVMXLIB_ENDPOINT_EVENT_OLDEVENTDATADECRYPTOR_HPP_

