/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/
#ifndef _PRIVMXLIB_ENDPOINT_EVENT_DATAENCRYPTORV5_HPP_
#define _PRIVMXLIB_ENDPOINT_EVENT_DATAENCRYPTORV5_HPP_

#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/encryptors/DataEncryptorV4.hpp>
#include <privmx/endpoint/core/encryptors/DIO/DIOEncryptorV1.hpp>
#include <privmx/endpoint/core/ServerTypes.hpp>
#include <privmx/endpoint/core/Types.hpp>
#include "privmx/endpoint/event/EventTypes.hpp"
#include "privmx/endpoint/event/ServerTypes.hpp"

namespace privmx {
namespace endpoint {
namespace event {

class EventDataEncryptorV5 {
public:
    server::EncryptedContextEventDataV5 encrypt(
        const ContextEventDataToEncryptV5& eventData,
        const crypto::PrivateKey& authorPrivateKey,
        const std::string& encryptionKey
    );
    DecryptedEventDataV5 decrypt(const server::EncryptedContextEventDataV5& encryptedEventData, const crypto::PublicKey& authorPublicKey, const std::string& encryptionKey);
private:
    core::DataIntegrityObject getDIOAndAssertIntegrity(const server::EncryptedContextEventDataV5& encryptedEventData, const crypto::PublicKey& authorPublicKey);
    void assertDataFormat(const server::EncryptedContextEventDataV5& encryptedEventData);
    core::DataEncryptorV4 _dataEncryptor;
    core::DIOEncryptorV1 _DIOEncryptor;
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  //_PRIVMXLIB_ENDPOINT_EVENT_DATAENCRYPTORV5_HPP_

