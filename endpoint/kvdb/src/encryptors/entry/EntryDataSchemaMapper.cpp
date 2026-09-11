/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/kvdb/encryptors/entry/EntryDataSchemaMapper.hpp"

#include <Poco/JSON/Object.h>
#include <privmx/endpoint/core/encryptors/DataSchemaMapperUtils.hpp>

#include "privmx/endpoint/kvdb/KvdbException.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::kvdb;

EntryDataSchemaMapper::EntryDataSchemaMapper(
    const privmx::crypto::PrivateKey& userPrivKey,
    const core::Connection& connection
)
    : _userPrivKey(userPrivKey), _connection(connection) {
    _strategyV5 = std::make_shared<EntryDataSchemaStrategyV5>();
    _strategyMapper.registerStrategy(KvdbEntryDataSchema::Version::VERSION_5, _strategyV5);
}

Poco::Dynamic::Var EntryDataSchemaMapper::encrypt(
    const std::string& kvdbId,
    const std::string& resourceId,
    const std::string& contextId,
    const std::string& moduleResourceId,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const core::Buffer& data,
    const core::DecryptedEncKeyV2& entryKey
) {
    switch (entryKey.dataStructureVersion) {
    case core::EncryptionKeyDataSchema::Version::UNKNOWN:
    case core::EncryptionKeyDataSchema::Version::VERSION_1:
        throw UnknownKvdbEntryFormatException();
    case core::EncryptionKeyDataSchema::Version::VERSION_2: {
        auto entryDIO = _connection.getImpl()->createDIO(contextId, resourceId, kvdbId, moduleResourceId);
        KvdbEntryDataToEncryptV5 entryData{
            .publicMeta = publicMeta,
            .privateMeta = privateMeta,
            .data = data,
            .internalMeta = std::nullopt,
            .dio = entryDIO
        };
        return _encryptorV5.encrypt(entryData, _userPrivKey, entryKey.key).toJSON();
    }
    }
    throw UnknownKvdbEntryFormatException();
}

std::tuple<KvdbEntry, core::DataIntegrityObject> EntryDataSchemaMapper::decrypt(
    const server::KvdbEntryInfo& entry,
    const core::DecryptedEncKey& encKey
) {
    return _strategyMapper.dispatch(
        static_cast<int64_t>(getDataStructureVersion(entry)), entry, encKey,
        [&]() -> std::tuple<KvdbEntry, core::DataIntegrityObject> {
            return {
                toLibKvdbEntry(
                    entry, {}, {}, {}, {}, UnknownKvdbEntryFormatException().getCode(),
                    KvdbEntryDataSchema::Version::UNKNOWN
                ),
                {}
            };
        }
    );
}

KvdbEntryDataSchema::Version EntryDataSchemaMapper::getDataStructureVersion(const server::KvdbEntryInfo& entry) {
    return core::DataSchemaMapperUtils::mapVersionedData(
        entry.kvdbEntryValue, KvdbEntryDataSchema::Version::UNKNOWN,
        [](int64_t v) {
            switch (v) {
            case KvdbEntryDataSchema::Version::VERSION_5:
                return KvdbEntryDataSchema::Version::VERSION_5;
            default:
                return KvdbEntryDataSchema::Version::UNKNOWN;
            }
        }
    );
}

uint32_t EntryDataSchemaMapper::validateEntryDataIntegrity(
    const server::KvdbEntryInfo& entry,
    const std::string& kvdbResourceId
) {
    return core::DataSchemaMapperUtils::toStatusCode([&] {
        switch (getDataStructureVersion(entry)) {
        case KvdbEntryDataSchema::Version::UNKNOWN:
            throw UnknownKvdbEntryFormatException();
        case KvdbEntryDataSchema::Version::VERSION_5: {
            auto encData = server::EncryptedKvdbEntryDataV5::fromJSON(entry.kvdbEntryValue);
            auto dio = _strategyV5->getDIOAndAssertIntegrity(encData);
            core::DataSchemaMapperUtils::assertEntryDIOIntegrity(
                dio, entry.contextId, entry.kvdbEntryKey, entry.kvdbId, kvdbResourceId, entry.lastModifier,
                entry.lastModificationDate, [] { throw KvdbEntryDataIntegrityException(); }
            );
            return;
        }
        default:
            throw UnknownKvdbEntryFormatException();
        }
    });
}

std::vector<KvdbEntry> EntryDataSchemaMapper::validateDecryptAndConvertKvdbEntriesDataToKvdbEntries(
    const std::vector<server::KvdbEntryInfo>& entries,
    const core::ModuleKeys& kvdbKeys,
    const std::shared_ptr<core::KeyProvider>& keyProvider,
    const core::KeyProvider::GroupPrivKeyResolver& groupPrivKeyResolver
) {
    return core::DataSchemaMapperUtils::batchValidateDecryptVerifyEntries<KvdbEntry>(
        entries, kvdbKeys, keyProvider, _connection,
        [&](const server::KvdbEntryInfo& e) { return validateEntryDataIntegrity(e, kvdbKeys.moduleResourceId); },
        [&](const server::KvdbEntryInfo& e, const core::DecryptedEncKey& key) { return decrypt(e, key); },
        [](const server::KvdbEntryInfo& e, uint32_t code) {
            return toLibKvdbEntry(e, {}, {}, {}, {}, code, KvdbEntryDataSchema::Version::UNKNOWN);
        },
        groupPrivKeyResolver
    );
}

KvdbEntry EntryDataSchemaMapper::validateDecryptAndConvertEntryDataToEntry(
    const server::KvdbEntryInfo& entry,
    const core::ModuleKeys& kvdbKeys,
    const std::shared_ptr<core::KeyProvider>& keyProvider,
    const core::KeyProvider::GroupPrivKeyResolver& groupPrivKeyResolver
) {
    return validateDecryptAndConvertKvdbEntriesDataToKvdbEntries(
        {entry}, kvdbKeys, keyProvider, groupPrivKeyResolver
    )[0];
}

KvdbEntry EntryDataSchemaMapper::toLibKvdbEntry(
    const server::KvdbEntryInfo& entry,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const core::Buffer& data,
    const std::string& authorPubKey,
    int64_t statusCode,
    int64_t schemaVersion
) {
    return KvdbEntry{
        .info =
            {
                .kvdbId = entry.kvdbId,
                .key = entry.kvdbEntryKey,
                .createDate = entry.createDate,
                .author = entry.author,
            },
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .data = data,
        .authorPubKey = authorPubKey,
        .version = entry.version,
        .statusCode = statusCode,
        .schemaVersion = schemaVersion
    };
}
