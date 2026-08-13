/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/kvdb/encryptors/kvdb/KvdbDataSchemaMapper.hpp"

#include "privmx/endpoint/kvdb/KvdbException.hpp"
#include <Poco/JSON/Object.h>
#include <privmx/endpoint/core/Factory.hpp>
#include <privmx/endpoint/core/encryptors/DataSchemaMapperUtils.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::kvdb;

KvdbDataSchemaMapper::KvdbDataSchemaMapper(
    const privmx::crypto::PrivateKey& userPrivKey,
    const core::Connection& connection
)
    : core::BaseModuleDataSchemaMapper(userPrivKey, connection) {
    _strategyV5 = std::make_shared<KvdbDataSchemaStrategyV5>();
    _strategyMapper.registerStrategy(core::ModuleDataSchema::Version::VERSION_5, _strategyV5);
}

Poco::Dynamic::Var KvdbDataSchemaMapper::encrypt(const core::ModuleDataToEncryptV5& data, const std::string& key) {
    return _encryptorV5.encrypt(data, _userPrivKey, key).toJSON();
}

std::tuple<Kvdb, core::DataIntegrityObject> KvdbDataSchemaMapper::decrypt(
    const server::KvdbInfo& kvdb,
    const core::DecryptedEncKey& encKey
) {
    return _strategyMapper.dispatch(
        static_cast<int64_t>(getDataStructureVersion(kvdb.data.back())), kvdb, encKey,
        [&]() -> std::tuple<Kvdb, core::DataIntegrityObject> {
            return {
                toLibKvdb(kvdb, {}, {}, UnknownKvdbFormatException().getCode(), KvdbDataSchema::Version::UNKNOWN), {}
            };
        }
    );
}

void KvdbDataSchemaMapper::assertDataIntegrity(const server::KvdbInfo& kvdb) {
    const auto& entry = kvdb.data.back();
    switch (getDataStructureVersion(entry)) {
    case core::ModuleDataSchema::Version::UNKNOWN:
        throw UnknownKvdbFormatException(
            "dataStructureVersion=" + std::to_string((int64_t)getDataStructureVersion(entry))
        );
    case core::ModuleDataSchema::Version::VERSION_5: {
        core::DataSchemaMapperUtils::assertContainerV5DIOIntegrity(entry.data, kvdb, _strategyV5, [] {
            throw KvdbDataIntegrityException();
        });
        return;
    }
    default:
        throw UnknownKvdbFormatException(
            "dataStructureVersion=" + std::to_string((int64_t)getDataStructureVersion(entry))
        );
    }
}

uint32_t KvdbDataSchemaMapper::validateDataIntegrity(const server::KvdbInfo& kvdb) {
    return core::DataSchemaMapperUtils::toStatusCode([&] { assertDataIntegrity(kvdb); });
}

std::vector<Kvdb> KvdbDataSchemaMapper::validateDecryptAndConvertKvdbs(
    const std::vector<server::KvdbInfo>& kvdbs,
    const std::shared_ptr<core::KeyProvider>& keyProvider
) {
    return core::DataSchemaMapperUtils::batchValidateDecryptVerifyContainers<Kvdb>(
        kvdbs, keyProvider, _connection, [&](const server::KvdbInfo& k) { return validateDataIntegrity(k); },
        [](const server::KvdbInfo& k) -> core::EncKeyLocation {
            return {.contextId = k.contextId, .resourceId = k.resourceId.value_or("")};
        },
        [&](const server::KvdbInfo& k, const core::DecryptedEncKey& key) { return decrypt(k, key); },
        [](const server::KvdbInfo& k, uint32_t code) {
            return toLibKvdb(k, {}, {}, code, KvdbDataSchema::Version::UNKNOWN);
        }
    );
}

Kvdb KvdbDataSchemaMapper::validateDecryptAndConvertKvdb(
    const server::KvdbInfo& kvdb,
    const std::shared_ptr<core::KeyProvider>& keyProvider
) {
    return validateDecryptAndConvertKvdbs({kvdb}, keyProvider)[0];
}

Kvdb KvdbDataSchemaMapper::toLibKvdb(
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