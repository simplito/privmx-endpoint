/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_STOREDATASCHEMAMAPPER_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_STOREDATASCHEMAMAPPER_HPP_

#include <cstdint>
#include <memory>
#include <string>
#include <tuple>
#include <vector>

#include <Poco/Dynamic/Var.h>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/KeyProvider.hpp>
#include <privmx/endpoint/core/encryptors/VersionStrategyMapper.hpp>
#include <privmx/endpoint/core/encryptors/module/Types.hpp>

#include "privmx/endpoint/store/Constants.hpp"
#include "privmx/endpoint/store/ServerTypes.hpp"
#include "privmx/endpoint/store/Types.hpp"
#include "privmx/endpoint/store/encryptors/store/StoreDataSchemaStrategyV4.hpp"
#include "privmx/endpoint/store/encryptors/store/StoreDataSchemaStrategyV5.hpp"

namespace privmx {
namespace endpoint {
namespace store {

class StoreDataSchemaMapper {
public:
    StoreDataSchemaMapper(const privmx::crypto::PrivateKey& userPrivKey, const core::Connection& connection);

    Poco::Dynamic::Var encrypt(const core::ModuleDataToEncryptV5& data, const std::string& key);

    std::tuple<Store, core::DataIntegrityObject> decrypt(
        const server::Store& store,
        const core::DecryptedEncKey& encKey
    );

    StoreDataSchema::Version getDataStructureVersion(const server::StoreDataEntry& entry);

    void assertDataIntegrity(const server::Store& store);

    uint32_t validateDataIntegrity(const server::Store& store);

    std::vector<Store> validateDecryptAndConvertStores(
        std::vector<server::Store> stores,
        const std::shared_ptr<core::KeyProvider>& keyProvider
    );

    Store validateDecryptAndConvertStore(server::Store store, const std::shared_ptr<core::KeyProvider>& keyProvider);

    static Store toLibStore(
        const server::Store& store,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        int64_t statusCode,
        int64_t schemaVersion
    );

private:
    privmx::crypto::PrivateKey _userPrivKey;
    core::Connection _connection;
    core::VersionStrategyMapper<server::Store, std::tuple<Store, core::DataIntegrityObject>> _strategyMapper;
    std::shared_ptr<StoreDataSchemaStrategyV4> _strategyV4;
    std::shared_ptr<StoreDataSchemaStrategyV5> _strategyV5;
};

} // namespace store
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_STOREDATASCHEMAMAPPER_HPP_
