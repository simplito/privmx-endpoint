/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_KVDB_KVDBDATASCHEMAMAPPER_HPP_
#define _PRIVMXLIB_ENDPOINT_KVDB_KVDBDATASCHEMAMAPPER_HPP_

#include <cstdint>
#include <memory>
#include <string>
#include <tuple>
#include <vector>

#include <Poco/Dynamic/Var.h>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/DynamicTypes.hpp>
#include <privmx/endpoint/core/KeyProvider.hpp>
#include <privmx/endpoint/core/TimestampValidator.hpp>
#include <privmx/endpoint/core/encryptors/VersionStrategyMapper.hpp>
#include <privmx/endpoint/core/encryptors/module/ModuleDataEncryptorV5.hpp>
#include <privmx/endpoint/core/encryptors/module/Types.hpp>

#include "privmx/endpoint/kvdb/Constants.hpp"
#include "privmx/endpoint/kvdb/ServerTypes.hpp"
#include "privmx/endpoint/kvdb/Types.hpp"
#include "privmx/endpoint/kvdb/encryptors/kvdb/KvdbDataSchemaStrategyV5.hpp"

namespace privmx {
namespace endpoint {
namespace kvdb {

class KvdbDataSchemaMapper {
public:
    KvdbDataSchemaMapper(const privmx::crypto::PrivateKey& userPrivKey, const core::Connection& connection);

    Poco::Dynamic::Var encrypt(const core::ModuleDataToEncryptV5& data, const std::string& key);

    std::tuple<Kvdb, core::DataIntegrityObject> decrypt(
        const server::KvdbInfo& kvdb,
        const core::DecryptedEncKey& encKey
    );

    KvdbDataSchema::Version getDataStructureVersion(const server::KvdbDataEntry& entry);

    void assertDataIntegrity(const server::KvdbInfo& kvdb);

    uint32_t validateDataIntegrity(const server::KvdbInfo& kvdb);

    std::vector<Kvdb> validateDecryptAndConvertKvdbs(
        const std::vector<server::KvdbInfo>& kvdbs,
        const std::shared_ptr<core::KeyProvider>& keyProvider
    );

    Kvdb validateDecryptAndConvertKvdb(
        const server::KvdbInfo& kvdb,
        const std::shared_ptr<core::KeyProvider>& keyProvider
    );

private:
    privmx::crypto::PrivateKey _userPrivKey;
    core::Connection _connection;
    core::VersionStrategyMapper<server::KvdbInfo, std::tuple<Kvdb, core::DataIntegrityObject>> _strategyMapper;
    std::shared_ptr<KvdbDataSchemaStrategyV5> _strategyV5;
    core::ModuleDataEncryptorV5 _encryptorV5;
};

} // namespace kvdb
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_KVDB_KVDBDATAENCRYPTORMAPPER_HPP_
