/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_MESSAGEDATAENCRYPTORV4_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_MESSAGEDATAENCRYPTORV4_HPP_

#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/encryptors/DataEncryptorV4.hpp>
#include <privmx/endpoint/core/ServerTypes.hpp>
#include <privmx/endpoint/core/Types.hpp>
#include "privmx/endpoint/thread/ThreadTypes.hpp"
#include "privmx/endpoint/thread/ServerTypes.hpp"

namespace privmx {
namespace endpoint {
namespace thread {

class MessageDataEncryptorV4 {
public:
    server::EncryptedMessageDataV4 encrypt(const MessageDataToEncrypt& messageData,
                                                 const crypto::PrivateKey& authorPrivateKey,
                                                 const std::string& encryptionKey);
    DecryptedMessageData decrypt(const server::EncryptedMessageDataV4& encryptedMessageData,
                                       const std::string& encryptionKey);

private:
    void validateVersion(const server::EncryptedMessageDataV4& encryptedMessageData);

    core::DataEncryptorV4 _dataEncryptor;
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  //_PRIVMXLIB_ENDPOINT_CORE_MESSAGEDATAENCRYPTORV4_HPP_
