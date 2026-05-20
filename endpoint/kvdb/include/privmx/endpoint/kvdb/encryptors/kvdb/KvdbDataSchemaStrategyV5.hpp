/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_KVDB_KVDBDATASCHEMASTRATEGYV5_HPP_
#define _PRIVMXLIB_ENDPOINT_KVDB_KVDBDATASCHEMASTRATEGYV5_HPP_

#include <tuple>

#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/DynamicTypes.hpp>
#include <privmx/endpoint/core/encryptors/TypedDataSchemaStrategy.hpp>
#include <privmx/endpoint/core/encryptors/module/ModuleDataEncryptorV5.hpp>
#include <privmx/endpoint/core/encryptors/module/Types.hpp>

#include "privmx/endpoint/kvdb/Constants.hpp"
#include "privmx/endpoint/kvdb/ServerTypes.hpp"
#include "privmx/endpoint/kvdb/Types.hpp"

namespace privmx {
namespace endpoint {
namespace kvdb {

// clang-format off
class KvdbDataSchemaStrategyV5 : public core::TypedDataSchemaStrategy<
    server::KvdbInfo,
    core::DecryptedModuleDataV5,
    std::tuple<Kvdb, core::DataIntegrityObject>
> {
    // clang-format on
public:
    core::DecryptedModuleDataV5 decrypt(
        const server::KvdbInfo& kvdb,
        const core::DecryptedEncKey& encKey
    ) const override;
    std::tuple<Kvdb, core::DataIntegrityObject> convert(
        const server::KvdbInfo& kvdb,
        const core::DecryptedModuleDataV5& raw
    ) const override;
    std::tuple<Kvdb, core::DataIntegrityObject> makeErrorResult(
        const server::KvdbInfo& kvdb,
        int64_t errorCode
    ) const override;
    core::DataIntegrityObject getDIOAndAssertIntegrity(const core::dynamic::EncryptedModuleDataV5& encData) const;

    static Kvdb toLibKvdb(
        const server::KvdbInfo& info,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        int64_t statusCode,
        int64_t schemaVersion
    );

private:
    mutable core::ModuleDataEncryptorV5 _encryptor;
};

} // namespace kvdb
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_KVDB_KVDBDATASCHEMASTRATEGYV5_HPP_
