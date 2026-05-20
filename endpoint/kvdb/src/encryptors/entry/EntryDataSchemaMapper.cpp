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
#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/ConvertedExceptions.hpp>
#include <privmx/endpoint/core/CoreConstants.hpp>
#include <privmx/endpoint/core/DynamicTypes.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/endpoint/core/TimestampValidator.hpp>

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
    auto version = getDataStructureVersion(entry);
    auto strategy = _strategyMapper.getStrategy(static_cast<int64_t>(version));
    if (!strategy) {
        auto e = UnknownKvdbEntryFormatException();
        return {
            EntryDataSchemaStrategyV5::toLibKvdbEntry(
                entry, {}, {}, {}, {}, e.getCode(), KvdbEntryDataSchema::Version::UNKNOWN
            ),
            core::DataIntegrityObject{}
        };
    }
    return strategy->decryptAndConvert(entry, encKey);
}

KvdbEntryDataSchema::Version EntryDataSchemaMapper::getDataStructureVersion(const server::KvdbEntryInfo& entry) {
    if (entry.kvdbEntryValue.type() == typeid(Poco::JSON::Object::Ptr)) {
        auto versioned = core::dynamic::VersionedData::fromJSON(entry.kvdbEntryValue);
        switch (versioned.version) {
        case KvdbEntryDataSchema::Version::VERSION_5:
            return KvdbEntryDataSchema::Version::VERSION_5;
        default:
            return KvdbEntryDataSchema::Version::UNKNOWN;
        }
    }
    return KvdbEntryDataSchema::Version::UNKNOWN;
}

uint32_t EntryDataSchemaMapper::validateEntryDataIntegrity(
    const server::KvdbEntryInfo& entry,
    const std::string& kvdbResourceId
) {
    try {
        switch (getDataStructureVersion(entry)) {
        case KvdbEntryDataSchema::Version::UNKNOWN:
            return UnknownKvdbEntryFormatException().getCode();
        case KvdbEntryDataSchema::Version::VERSION_5: {
            auto encData = server::EncryptedKvdbEntryDataV5::fromJSON(entry.kvdbEntryValue);
            auto dio = _strategyV5->getDIOAndAssertIntegrity(encData);
            if (dio.contextId != entry.contextId ||
                dio.resourceId != entry.kvdbEntryKey ||
                !dio.containerId.has_value() ||
                dio.containerId.value() != entry.kvdbId ||
                !dio.containerResourceId.has_value() ||
                dio.containerResourceId.value() != kvdbResourceId ||
                dio.creatorUserId != entry.lastModifier ||
                !core::TimestampValidator::validate(dio.timestamp, entry.lastModificationDate)) {
                return KvdbEntryDataIntegrityException().getCode();
            }
            return 0;
        }
        }
    } catch (const core::Exception& e) { return e.getCode(); } catch (const privmx::utils::PrivmxException& e) {
        return core::ExceptionConverter::convert(e).getCode();
    } catch (...) { return ENDPOINT_CORE_EXCEPTION_CODE; }
    return UnknownKvdbEntryFormatException().getCode();
}

std::vector<KvdbEntry> EntryDataSchemaMapper::validateDecryptAndConvertKvdbEntriesDataToKvdbEntries(
    std::vector<server::KvdbEntryInfo> entries,
    const core::ModuleKeys& kvdbKeys,
    const std::shared_ptr<core::KeyProvider>& keyProvider
) {
    if (entries.empty()) {
        return {};
    }

    std::vector<KvdbEntry> result(entries.size());
    std::vector<core::DataIntegrityObject> entriesDIO(entries.size());
    std::set<std::string> seenRandomIds;

    for (size_t i = 0; i < entries.size(); i++) {
        auto code = validateEntryDataIntegrity(entries[i], kvdbKeys.moduleResourceId);
        if (code != 0) {
            result[i] = EntryDataSchemaStrategyV5::toLibKvdbEntry(
                entries[i], {}, {}, {}, {}, code, KvdbEntryDataSchema::Version::UNKNOWN
            );
        }
    }

    const core::EncKeyLocation location{.contextId = kvdbKeys.contextId, .resourceId = kvdbKeys.moduleResourceId};
    core::KeyDecryptionAndVerificationRequest keyRequest;
    for (size_t i = 0; i < entries.size(); i++) {
        if (result[i].statusCode != 0) {
            continue;
        }
        keyRequest.addOne(kvdbKeys.keys, entries[i].keyId, location);
    }
    auto keysResult = keyProvider->getKeysAndVerify(keyRequest);
    auto keyMapIt = keysResult.find(location);

    for (size_t i = 0; i < entries.size(); i++) {
        if (result[i].statusCode != 0) {
            continue;
        }
        try {
            auto [decryptedEntry, dio] = decrypt(entries[i], keyMapIt->second.at(entries[i].keyId));
            result[i] = decryptedEntry;
            entriesDIO[i] = dio;
            if (!seenRandomIds.insert(dio.randomId + "-" + std::to_string(dio.timestamp)).second) {
                result[i].statusCode = core::DataIntegrityObjectDuplicatedException().getCode();
            }
        } catch (const core::Exception& e) {
            result[i] = EntryDataSchemaStrategyV5::toLibKvdbEntry(
                entries[i], {}, {}, {}, {}, e.getCode(), KvdbEntryDataSchema::Version::UNKNOWN
            );
        }
    }

    std::vector<core::VerificationRequest> verifyRequests;
    std::vector<size_t> verifyIndices;
    for (size_t i = 0; i < result.size(); i++) {
        if (result[i].statusCode != 0) {
            continue;
        }
        verifyRequests.push_back(
            {.contextId = kvdbKeys.contextId,
             .senderId = result[i].info.author,
             .senderPubKey = result[i].authorPubKey,
             .date = result[i].info.createDate,
             .bridgeIdentity = entriesDIO[i].bridgeIdentity}
        );
        verifyIndices.push_back(i);
    }
    auto verified = _connection.getImpl()->getUserVerifier()->verify(verifyRequests);
    for (size_t j = 0; j < verifyIndices.size(); j++) {
        result[verifyIndices[j]].statusCode = verified[j] ?
            0 :
            core::ExceptionConverter::getCodeOfUserVerificationFailureException();
    }
    return result;
}

KvdbEntry EntryDataSchemaMapper::validateDecryptAndConvertEntryDataToEntry(
    server::KvdbEntryInfo entry,
    const core::ModuleKeys& kvdbKeys,
    const std::shared_ptr<core::KeyProvider>& keyProvider
) {
    return validateDecryptAndConvertKvdbEntriesDataToKvdbEntries({std::move(entry)}, kvdbKeys, keyProvider)[0];
}
