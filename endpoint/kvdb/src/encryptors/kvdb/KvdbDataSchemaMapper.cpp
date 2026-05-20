/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/kvdb/encryptors/kvdb/KvdbDataSchemaMapper.hpp"

#include <Poco/JSON/Object.h>
#include <map>
#include <set>
#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/ConvertedExceptions.hpp>
#include <privmx/endpoint/core/CoreConstants.hpp>
#include <privmx/endpoint/core/DynamicTypes.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/endpoint/core/TimestampValidator.hpp>

#include "privmx/endpoint/kvdb/KvdbException.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::kvdb;

KvdbDataSchemaMapper::KvdbDataSchemaMapper(
    const privmx::crypto::PrivateKey& userPrivKey,
    const core::Connection& connection
)
    : _userPrivKey(userPrivKey), _connection(connection) {
    _strategyV5 = std::make_shared<KvdbDataSchemaStrategyV5>();
    _strategyMapper.registerStrategy(KvdbDataSchema::Version::VERSION_5, _strategyV5);
}

Poco::Dynamic::Var KvdbDataSchemaMapper::encrypt(
    const core::ModuleDataToEncryptV5& data,
    const std::string& key
) {
    return _encryptorV5.encrypt(data, _userPrivKey, key).toJSON();
}

std::tuple<Kvdb, core::DataIntegrityObject> KvdbDataSchemaMapper::decrypt(
    const server::KvdbInfo& kvdb,
    const core::DecryptedEncKey& encKey
) {
    auto version = getDataStructureVersion(kvdb.data.back());
    auto strategy = _strategyMapper.getStrategy(static_cast<int64_t>(version));
    if (!strategy) {
        auto e = UnknownKvdbFormatException();
        return {KvdbDataSchemaStrategyV5::toLibKvdb(kvdb, {}, {}, e.getCode(), KvdbDataSchema::Version::UNKNOWN),
                core::DataIntegrityObject{}};
    }
    return strategy->decryptAndConvert(kvdb, encKey);
}

KvdbDataSchema::Version KvdbDataSchemaMapper::getDataStructureVersion(
    const server::KvdbDataEntry& entry
) {
    if (entry.data.type() == typeid(Poco::JSON::Object::Ptr)) {
        auto versioned = core::dynamic::VersionedData::fromJSON(entry.data);
        switch (versioned.version) {
        case core::ModuleDataSchema::Version::VERSION_5:
            return KvdbDataSchema::Version::VERSION_5;
        default:
            return KvdbDataSchema::Version::UNKNOWN;
        }
    }
    return KvdbDataSchema::Version::UNKNOWN;
}

void KvdbDataSchemaMapper::assertDataIntegrity(const server::KvdbInfo& kvdb) {
    const auto& entry = kvdb.data.back();
    switch (getDataStructureVersion(entry)) {
    case KvdbDataSchema::Version::UNKNOWN:
        throw UnknownKvdbFormatException();
    case KvdbDataSchema::Version::VERSION_5: {
        auto encData = core::dynamic::EncryptedModuleDataV5::fromJSON(entry.data);
        auto dio = _strategyV5->getDIOAndAssertIntegrity(encData);
        if (dio.contextId != kvdb.contextId ||
            dio.resourceId != kvdb.resourceId ||
            dio.creatorUserId != kvdb.lastModifier ||
            !core::TimestampValidator::validate(dio.timestamp, kvdb.lastModificationDate)) {
            throw KvdbDataIntegrityException();
        }
        return;
    }
    }
    throw UnknownKvdbFormatException();
}

uint32_t KvdbDataSchemaMapper::validateDataIntegrity(const server::KvdbInfo& kvdb) {
    try {
        assertDataIntegrity(kvdb);
        return 0;
    } catch (const core::Exception& e) { return e.getCode(); } catch (const privmx::utils::PrivmxException& e) {
        return core::ExceptionConverter::convert(e).getCode();
    } catch (...) { return ENDPOINT_CORE_EXCEPTION_CODE; }
}

std::vector<Kvdb> KvdbDataSchemaMapper::validateDecryptAndConvertKvdbs(
    const std::vector<server::KvdbInfo>& kvdbs,
    const std::shared_ptr<core::KeyProvider>& keyProvider
) {
    std::vector<Kvdb> result(kvdbs.size());
    std::vector<core::DataIntegrityObject> result_dio(kvdbs.size());

    for (size_t i = 0; i < kvdbs.size(); i++) {
        auto code = validateDataIntegrity(kvdbs[i]);
        if (code != 0) {
            result[i] = KvdbDataSchemaStrategyV5::toLibKvdb(kvdbs[i], {}, {}, code, KvdbDataSchema::Version::UNKNOWN);
        }
    }

    core::KeyDecryptionAndVerificationRequest keyRequest;
    for (size_t i = 0; i < kvdbs.size(); i++) {
        if (result[i].statusCode != 0) continue;
        const auto& kvdb = kvdbs[i];
        core::EncKeyLocation loc{.contextId = kvdb.contextId, .resourceId = kvdb.resourceId};
        keyRequest.addOne(kvdb.keys, kvdb.data.back().keyId, loc);
    }
    auto kvdbKeys = keyProvider->getKeysAndVerify(keyRequest);
    std::set<std::string> seenRandomIds;

    for (size_t i = 0; i < kvdbs.size(); i++) {
        if (result[i].statusCode != 0) continue;
        const auto& kvdb = kvdbs[i];
        core::EncKeyLocation loc{.contextId = kvdb.contextId, .resourceId = kvdb.resourceId};
        try {
            auto it = kvdbKeys.find(loc);
            if (it == kvdbKeys.end()) throw UnknownKvdbFormatException();
            auto [decryptedKvdb, dio] = decrypt(kvdb, it->second.at(kvdb.data.back().keyId));
            result[i] = decryptedKvdb;
            result_dio[i] = dio;
            if (!seenRandomIds.insert(dio.randomId + "-" + std::to_string(dio.timestamp)).second) {
                result[i].statusCode = core::DataIntegrityObjectDuplicatedException().getCode();
            }
        } catch (const core::Exception& e) {
            result[i] = KvdbDataSchemaStrategyV5::toLibKvdb(kvdb, {}, {}, e.getCode(), KvdbDataSchema::Version::UNKNOWN);
        }
    }

    std::vector<core::VerificationRequest> verifyRequests;
    std::vector<size_t> verifyIndices;
    for (size_t i = 0; i < result.size(); i++) {
        if (result[i].statusCode != 0) continue;
        verifyRequests.push_back(
            {.contextId = result[i].contextId,
             .senderId = result[i].lastModifier,
             .senderPubKey = result_dio[i].creatorPubKey,
             .date = result[i].lastModificationDate,
             .bridgeIdentity = result_dio[i].bridgeIdentity}
        );
        verifyIndices.push_back(i);
    }
    auto verified = _connection.getImpl()->getUserVerifier()->verify(verifyRequests);
    for (size_t j = 0; j < verifyIndices.size(); j++) {
        result[verifyIndices[j]].statusCode =
            verified[j] ? 0 : core::ExceptionConverter::getCodeOfUserVerificationFailureException();
    }
    return result;
}

Kvdb KvdbDataSchemaMapper::validateDecryptAndConvertKvdb(
    const server::KvdbInfo& kvdb,
    const std::shared_ptr<core::KeyProvider>& keyProvider
) {
    return validateDecryptAndConvertKvdbs({kvdb}, keyProvider)[0];
}

