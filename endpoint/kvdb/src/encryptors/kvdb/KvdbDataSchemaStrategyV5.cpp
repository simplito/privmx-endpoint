/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/kvdb/encryptors/kvdb/KvdbDataSchemaStrategyV5.hpp"

#include <privmx/endpoint/core/Factory.hpp>

#include "privmx/endpoint/kvdb/Constants.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::kvdb;

core::DecryptedModuleDataV5 KvdbDataSchemaStrategyV5::decrypt(
    const server::KvdbInfo& kvdb,
    const core::DecryptedEncKey& encKey
) const {
    auto encryptedData = core::dynamic::EncryptedModuleDataV5::fromJSON(kvdb.data.back().data);
    core::DecryptedModuleDataV5 result;
    if (encKey.statusCode != 0) {
        result = _encryptor.extractPublic(encryptedData);
        result.statusCode = encKey.statusCode;
    } else {
        result = _encryptor.decrypt(encryptedData, encKey.key);
    }
    return result;
}

std::tuple<Kvdb, core::DataIntegrityObject> KvdbDataSchemaStrategyV5::convert(
    const server::KvdbInfo& kvdb,
    const core::DecryptedModuleDataV5& raw
) const {
    return {
        toLibKvdb(kvdb, raw.publicMeta, raw.privateMeta, raw.statusCode, KvdbDataSchema::Version::VERSION_5), raw.dio
    };
}

std::tuple<Kvdb, core::DataIntegrityObject> KvdbDataSchemaStrategyV5::makeErrorResult(
    const server::KvdbInfo& kvdb,
    int64_t errorCode
) const {
    return {toLibKvdb(kvdb, {}, {}, errorCode, KvdbDataSchema::Version::VERSION_5), core::DataIntegrityObject{}};
}

core::DataIntegrityObject KvdbDataSchemaStrategyV5::getDIOAndAssertIntegrity(
    const core::dynamic::EncryptedModuleDataV5& encData
) const {
    return _encryptor.getDIOAndAssertIntegrity(encData);
}

Kvdb KvdbDataSchemaStrategyV5::toLibKvdb(
    const server::KvdbInfo& info,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    int64_t statusCode,
    int64_t schemaVersion
) {
    return Kvdb{
        .contextId = info.contextId,
        .kvdbId = info.id,
        .createDate = info.createDate,
        .creator = info.creator,
        .lastModificationDate = info.lastModificationDate,
        .lastModifier = info.lastModifier,
        .users = info.users,
        .managers = info.managers,
        .version = info.version,
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .entries = info.entries,
        .lastEntryDate = info.lastEntryDate,
        .policy = core::Factory::parsePolicyServerObject(info.policy),
        .statusCode = statusCode,
        .schemaVersion = schemaVersion
    };
}
