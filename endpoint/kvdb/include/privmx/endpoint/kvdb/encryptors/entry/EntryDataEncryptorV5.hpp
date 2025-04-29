/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_KVDB_ITEMDATAENCRYPTORV5_HPP_
#define _PRIVMXLIB_ENDPOINT_KVDB_ITEMDATAENCRYPTORV5_HPP_

#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/encryptors/DataEncryptorV4.hpp>
#include <privmx/endpoint/core/encryptors/DIO/DIOEncryptorV1.hpp>
#include <privmx/endpoint/core/ServerTypes.hpp>
#include <privmx/endpoint/core/Types.hpp>
#include "privmx/endpoint/kvdb/KvdbTypes.hpp"
#include "privmx/endpoint/kvdb/ServerTypes.hpp"

namespace privmx {
namespace endpoint {
namespace kvdb {

class EntryDataEncryptorV5 {
public:
    server::EncryptedKvdbEntryDataV5 encrypt(
        const KvdbEntryDataToEncryptV5& messageData,
        const crypto::PrivateKey& authorPrivateKey,
        const std::string& encryptionKey
    );
    DecryptedKvdbEntryDataV5 decrypt(const server::EncryptedKvdbEntryDataV5& encryptedItemData, const std::string& encryptionKey);
    DecryptedKvdbEntryDataV5 extractPublic(const server::EncryptedKvdbEntryDataV5& encryptedItemData);
    core::DataIntegrityObject getDIOAndAssertIntegrity(const server::EncryptedKvdbEntryDataV5& encryptedItemData);
private:
    void assertDataFormat(const server::EncryptedKvdbEntryDataV5& encryptedKvdbData);
    core::DataEncryptorV4 _dataEncryptor;
    core::DIOEncryptorV1 _DIOEncryptor;
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  //_PRIVMXLIB_ENDPOINT_KVDB_ITEMDATAENCRYPTORV5_HPP_
