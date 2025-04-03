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

#include "privmx/endpoint/core/CoreTypes.hpp"
#include "privmx/endpoint/core/DataEncryptorV4.hpp"
#include "privmx/endpoint/core/ServerTypes.hpp"
#include "privmx/endpoint/core/Types.hpp"
#include "privmx/endpoint/kvdb/KvdbTypes.hpp"
#include "privmx/endpoint/kvdb/ServerTypes.hpp"

namespace privmx {
namespace endpoint {
namespace kvdb {

class KvdbItemDataEncryptorV4 {
public:
    server::EncryptedKvdbItemDataV4 encrypt(const KvdbItemDataToEncrypt& data,
                                                 const crypto::PrivateKey& authorPrivateKey,
                                                 const std::string& encryptionKey);
    DecryptedKvdbItemData decrypt(const server::EncryptedKvdbItemDataV4& encryptedKvdbItemData,
                                       const std::string& encryptionKey);

private:
    void validateVersion(const server::EncryptedKvdbItemDataV4& encryptedKvdbItemData);

    core::DataEncryptorV4 _dataEncryptor;
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  //_PRIVMXLIB_ENDPOINT_CORE_MESSAGEDATAENCRYPTORV4_HPP_
