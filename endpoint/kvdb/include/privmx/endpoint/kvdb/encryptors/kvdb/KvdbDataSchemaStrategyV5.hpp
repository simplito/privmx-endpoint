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
#include <privmx/endpoint/core/encryptors/TypedDataSchemaStrategyV5.hpp>
#include <privmx/endpoint/core/encryptors/module/ModuleDataEncryptorV5.hpp>
#include <privmx/endpoint/core/encryptors/module/Types.hpp>

#include "privmx/endpoint/kvdb/Constants.hpp"
#include "privmx/endpoint/kvdb/ServerTypes.hpp"
#include "privmx/endpoint/kvdb/Types.hpp"

namespace privmx {
namespace endpoint {
namespace kvdb {

// clang-format off
class KvdbDataSchemaStrategyV5 : public core::TypedDataSchemaStrategyV5<
    core::ModuleDataEncryptorV5,
    core::dynamic::EncryptedModuleDataV5,
    core::DecryptedModuleDataV5,
    server::KvdbInfo,
    Kvdb
> {
// clang-format on
public:
    std::tuple<Kvdb, core::DataIntegrityObject> convert(
        const server::KvdbInfo& kvdb,
        const core::DecryptedModuleDataV5& raw
    ) const override;
    Kvdb toLibError(const server::KvdbInfo& kvdb, int64_t errorCode) const override;

protected:
    core::dynamic::EncryptedModuleDataV5 getEncryptedData(const server::KvdbInfo& model) const override;
};

} // namespace kvdb
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_KVDB_KVDBDATASCHEMASTRATEGYV5_HPP_
