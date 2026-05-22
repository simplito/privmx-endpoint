/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/kvdb/encryptors/kvdb/KvdbDataSchemaStrategyV5.hpp"
#include "privmx/endpoint/kvdb/encryptors/kvdb/KvdbDataSchemaMapper.hpp"

#include <privmx/endpoint/core/Factory.hpp>

#include "privmx/endpoint/kvdb/Constants.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::kvdb;

core::dynamic::EncryptedModuleDataV5 KvdbDataSchemaStrategyV5::getEncryptedData(
    const server::KvdbInfo& model
) const {
    return core::dynamic::EncryptedModuleDataV5::fromJSON(model.data.back().data);
}

std::tuple<Kvdb, core::DataIntegrityObject> KvdbDataSchemaStrategyV5::convert(
    const server::KvdbInfo& kvdb,
    const core::DecryptedModuleDataV5& raw
) const {
    return {
        KvdbDataSchemaMapper::toLibKvdb(
            kvdb, raw.publicMeta, raw.privateMeta, raw.statusCode, KvdbDataSchema::Version::VERSION_5
        ),
        raw.dio
    };
}

std::tuple<Kvdb, core::DataIntegrityObject> KvdbDataSchemaStrategyV5::makeErrorResult(
    const server::KvdbInfo& kvdb,
    int64_t errorCode
) const {
    return {
        KvdbDataSchemaMapper::toLibKvdb(kvdb, {}, {}, errorCode, KvdbDataSchema::Version::VERSION_5),
        core::DataIntegrityObject{}
    };
}
