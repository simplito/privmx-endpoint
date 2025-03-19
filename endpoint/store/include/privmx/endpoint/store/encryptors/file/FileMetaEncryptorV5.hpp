/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_FILEMETAENCRYPTORV5_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_FILEMETAENCRYPTORV5_HPP_

#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/encryptors/DataEncryptorV4.hpp>
#include <privmx/endpoint/core/encryptors/DIO/DIOEncryptorV1.hpp>
#include <privmx/endpoint/core/ServerTypes.hpp>
#include <privmx/endpoint/core/Types.hpp>
#include "privmx/endpoint/store/ServerTypes.hpp"
#include "privmx/endpoint/store/StoreTypes.hpp"

namespace privmx {
namespace endpoint {
namespace store {

class FileMetaEncryptorV5 {
public:
    store::server::EncryptedFileMetaV5 encrypt(const store::FileMetaToEncryptV5& fileMeta,
                                              const crypto::PrivateKey& authorPrivateKey,
                                              const std::string& encryptionKey);
    store::DecryptedFileMetaV5 decrypt(const store::server::EncryptedFileMetaV5& encryptedFileMeta,
                                    const std::string& encryptionKey);
    store::DecryptedFileMetaV5 extractPublic(const store::server::EncryptedFileMetaV5& encryptedFileMeta);
    core::DataIntegrityObject getDIOAndAssertIntegrity(const server::EncryptedFileMetaV5& encryptedFileMeta);
private:
    void assertDataFormat(const store::server::EncryptedFileMetaV5& encryptedFileMeta);
    core::Buffer serializeNumber(const int64_t& number);
    int64_t deserializeNumber(const core::Buffer& buffer);

    core::DataEncryptorV4 _dataEncryptor;
    core::DIOEncryptorV1 _DIOEncryptor;

};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  //_PRIVMXLIB_ENDPOINT_CORE_FILEMETAENCRYPTORV5_HPP_
