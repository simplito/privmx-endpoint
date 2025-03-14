/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_MESSAGEDATAENCRYPTORV5_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_MESSAGEDATAENCRYPTORV5_HPP_

#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/encryptors/DataEncryptorV4.hpp>
#include <privmx/endpoint/core/encryptors/DIO/DIOEncryptorV1.hpp>
#include <privmx/endpoint/core/ServerTypes.hpp>
#include <privmx/endpoint/core/Types.hpp>
#include "privmx/endpoint/thread/ThreadTypes.hpp"
#include "privmx/endpoint/thread/ServerTypes.hpp"

namespace privmx {
namespace endpoint {
namespace thread {

class MessageDataEncryptorV5 {
public:
    server::EncryptedMessageDataV5 encrypt(
        const MessageDataToEncryptV5& messageData,
        const crypto::PrivateKey& authorPrivateKey,
        const std::string& encryptionKey
    );
    DecryptedMessageDataV5 decrypt(const server::EncryptedMessageDataV5& encryptedMessageData, const std::string& encryptionKey);
    core::DataIntegrityObject getDIOAndAssertIntegrity(const server::EncryptedMessageDataV5& encryptedMessageData);
private:
    void assertDataFormat(const server::EncryptedMessageDataV5& encryptedThreadData);
    core::DataEncryptorV4 _dataEncryptor;
    core::DIOEncryptorV1 _DIOEncryptor;
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  //_PRIVMXLIB_ENDPOINT_CORE_MESSAGEDATAENCRYPTORV5_HPP_
