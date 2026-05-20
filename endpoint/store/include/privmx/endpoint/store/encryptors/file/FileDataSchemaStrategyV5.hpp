/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_FILEDATASCHEMASTRATEGYV5_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_FILEDATASCHEMASTRATEGYV5_HPP_

#include <tuple>

#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/encryptors/TypedDataSchemaStrategy.hpp>

#include "privmx/endpoint/store/ServerTypes.hpp"
#include "privmx/endpoint/store/StoreTypes.hpp"
#include "privmx/endpoint/store/Types.hpp"
#include "privmx/endpoint/store/encryptors/file/FileMetaEncryptorV5.hpp"

namespace privmx {
namespace endpoint {
namespace store {

// clang-format off
class FileDataSchemaStrategyV5 : public core::TypedDataSchemaStrategy<
    server::File,
    DecryptedFileMetaV5,
    std::tuple<File, core::DataIntegrityObject>
> {
    // clang-format on
public:
    DecryptedFileMetaV5 decrypt(
        const server::File& file,
        const core::DecryptedEncKey& encKey
    ) const override;
    DecryptedFileMetaV5 decryptFileMeta(
        const server::File& file,
        const core::DecryptedEncKey& encKey
    ) const;
    std::tuple<File, core::DataIntegrityObject> convert(
        const server::File& file,
        const DecryptedFileMetaV5& raw
    ) const override;
    std::tuple<File, core::DataIntegrityObject> makeErrorResult(
        const server::File& file,
        int64_t errorCode
    ) const override;
    server::EncryptedFileMetaV5 encrypt(
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const core::Buffer& internalMeta,
        const privmx::crypto::PrivateKey& userPrivKey,
        const std::string& key,
        const core::DataIntegrityObject& dio
    ) const;
    core::DataIntegrityObject getDIOAndAssertIntegrity(
        const server::EncryptedFileMetaV5& encData
    ) const;

private:
    mutable FileMetaEncryptorV5 _encryptor;
};

} // namespace store
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_FILEDATASCHEMASTRATEGYV5_HPP_
