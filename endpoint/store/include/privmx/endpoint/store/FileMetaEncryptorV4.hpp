#ifndef _PRIVMXLIB_ENDPOINT_STORE_FILEMETAENCRYPTORV4_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_FILEMETAENCRYPTORV4_HPP_

#include "privmx/endpoint/core/CoreTypes.hpp"
#include "privmx/endpoint/core/DataEncryptorV4.hpp"
#include "privmx/endpoint/core/ServerTypes.hpp"
#include "privmx/endpoint/store/ServerTypes.hpp"
#include "privmx/endpoint/core/Types.hpp"
#include "privmx/endpoint/store/StoreTypes.hpp"

namespace privmx {
namespace endpoint {
namespace store {

class FileMetaEncryptorV4 {
public:
    store::server::EncryptedFileMetaV4 encrypt(const store::FileMetaToEncrypt& fileMeta,
                                              const crypto::PrivateKey& authorPrivateKey,
                                              const std::string& encryptionKey);
    store::DecryptedFileMeta decrypt(const store::server::EncryptedFileMetaV4& encryptedFileMeta,
                                    const std::string& encryptionKey);

private:
    void validateVersion(const store::server::EncryptedFileMetaV4& encryptedFileMeta);
    core::Buffer serializeNumber(const int64_t& number);
    int64_t deserializeNumber(const core::Buffer& buffer);

    core::DataEncryptorV4 _dataEncryptor;
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  //_PRIVMXLIB_ENDPOINT_CORE_FILEMETAENCRYPTORV4_HPP_
