/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/store/encryptors/store/StoreDataSchemaMapper.hpp"

#include <set>

#include <Poco/JSON/Object.h>
#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/CoreConstants.hpp>
#include <privmx/endpoint/core/DynamicTypes.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/endpoint/core/Factory.hpp>
#include <privmx/endpoint/core/TimestampValidator.hpp>

#include "privmx/endpoint/store/StoreException.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::store;

StoreDataSchemaMapper::StoreDataSchemaMapper(
    const privmx::crypto::PrivateKey& userPrivKey,
    const core::Connection& connection
)
    : _userPrivKey(userPrivKey), _connection(connection) {
    _strategyV4 = std::make_shared<StoreDataSchemaStrategyV4>();
    _strategyMapper.registerStrategy(StoreDataSchema::Version::VERSION_4, _strategyV4);
    _strategyV5 = std::make_shared<StoreDataSchemaStrategyV5>();
    _strategyMapper.registerStrategy(StoreDataSchema::Version::VERSION_5, _strategyV5);
}

Poco::Dynamic::Var StoreDataSchemaMapper::encrypt(const core::ModuleDataToEncryptV5& data, const std::string& key) {
    return _strategyV5->encrypt(data, _userPrivKey, key).toJSON();
}

std::tuple<Store, core::DataIntegrityObject> StoreDataSchemaMapper::decrypt(
    const server::Store& store,
    const core::DecryptedEncKey& encKey
) {
    auto version = getDataStructureVersion(store.data.back());
    auto strategy = _strategyMapper.getStrategy(static_cast<int64_t>(version));
    if (!strategy) {
        auto e = UnknowStoreFormatException();
        return {toLibStore(store, {}, {}, e.getCode(), StoreDataSchema::Version::UNKNOWN), core::DataIntegrityObject{}};
    }
    return strategy->decryptAndConvert(store, encKey);
}

StoreDataSchema::Version StoreDataSchemaMapper::getDataStructureVersion(const server::StoreDataEntry& entry) {
    if (entry.data.type() == typeid(Poco::JSON::Object::Ptr)) {
        auto versioned = core::dynamic::VersionedData::fromJSON(entry.data);
        switch (versioned.version) {
        case core::ModuleDataSchema::Version::VERSION_4:
            return StoreDataSchema::Version::VERSION_4;
        case core::ModuleDataSchema::Version::VERSION_5:
            return StoreDataSchema::Version::VERSION_5;
        default:
            return StoreDataSchema::Version::UNKNOWN;
        }
    }
    return StoreDataSchema::Version::UNKNOWN;
}

void StoreDataSchemaMapper::assertDataIntegrity(const server::Store& store) {
    const auto& entry = store.data.back();
    switch (getDataStructureVersion(entry)) {
    case StoreDataSchema::Version::UNKNOWN:
        throw UnknowStoreFormatException();
    case StoreDataSchema::Version::VERSION_4:
        return;
    case StoreDataSchema::Version::VERSION_5: {
        auto encData = core::dynamic::EncryptedModuleDataV5::fromJSON(entry.data);
        auto dio = _strategyV5->getDIOAndAssertIntegrity(encData);
        if (dio.contextId != store.contextId ||
            dio.resourceId != store.resourceId ||
            dio.creatorUserId != store.lastModifier ||
            !core::TimestampValidator::validate(dio.timestamp, store.lastModificationDate)) {
            throw StoreDataIntegrityException();
        }
        return;
    }
    default:
        throw UnknowStoreFormatException();
    }
}

uint32_t StoreDataSchemaMapper::validateDataIntegrity(const server::Store& store) {
    try {
        assertDataIntegrity(store);
        return 0;
    } catch (const core::Exception& e) { return e.getCode(); } catch (const privmx::utils::PrivmxException& e) {
        return core::ExceptionConverter::convert(e).getCode();
    } catch (...) { return ENDPOINT_CORE_EXCEPTION_CODE; }
}

std::vector<Store> StoreDataSchemaMapper::validateDecryptAndConvertStores(
    std::vector<server::Store> stores,
    const std::shared_ptr<core::KeyProvider>& keyProvider
) {
    if (stores.size() == 0) {
        return std::vector<Store>{};
    }
    std::vector<Store> result(stores.size());
    std::vector<core::DataIntegrityObject> storesDIO(stores.size());
    // integrity validation
    for (size_t i = 0; i < stores.size(); i++) {
        result[i].statusCode = validateDataIntegrity(stores[i]);
        if (result[i].statusCode != 0) {
            result[i] = toLibStore(stores[i], {}, {}, result[i].statusCode, StoreDataSchema::Version::UNKNOWN);
        } else {
            result[i].statusCode = 0;
        }
    }
    // batch key fetch
    core::KeyDecryptionAndVerificationRequest keyRequest;
    for (size_t i = 0; i < stores.size(); i++) {
        if (result[i].statusCode != 0) {
            continue;
        }
        auto& store = stores[i];
        core::EncKeyLocation location{.contextId = store.contextId, .resourceId = store.resourceId.value_or("")};
        keyRequest.addOne(store.keys, store.data.back().keyId, location);
    }
    auto storesKeys = keyProvider->getKeysAndVerify(keyRequest);
    std::set<std::string> seenRandomIds;
    // decrypt + deduplication
    for (size_t i = 0; i < stores.size(); i++) {
        if (result[i].statusCode != 0) {
            continue;
        }
        auto& store = stores[i];
        try {
            auto storeKeysIt = storesKeys.find(
                core::EncKeyLocation{.contextId = store.contextId, .resourceId = store.resourceId.value_or("")}
            );
            if (storeKeysIt == storesKeys.end()) {
                throw UnknowStoreFormatException();
            }
            auto [decryptedStore, dio] = decrypt(store, storeKeysIt->second.at(store.data.back().keyId));
            result[i] = decryptedStore;
            storesDIO[i] = dio;
            if (!seenRandomIds.insert(storesDIO[i].randomId + "-" + std::to_string(storesDIO[i].timestamp)).second) {
                result[i].statusCode = core::DataIntegrityObjectDuplicatedException().getCode();
            }
        } catch (const core::Exception& e) {
            result[i] = toLibStore(store, {}, {}, e.getCode(), StoreDataSchema::Version::UNKNOWN);
        }
    }
    // batch identity verification
    std::vector<core::VerificationRequest> verifyRequests;
    std::vector<size_t> verifyIndices;
    for (size_t i = 0; i < result.size(); i++) {
        if (result[i].statusCode != 0) {
            continue;
        }
        verifyRequests.push_back(
            {.contextId = result[i].contextId,
             .senderId = result[i].lastModifier,
             .senderPubKey = storesDIO[i].creatorPubKey,
             .date = result[i].lastModificationDate,
             .bridgeIdentity = storesDIO[i].bridgeIdentity}
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

Store StoreDataSchemaMapper::validateDecryptAndConvertStore(
    server::Store store,
    const std::shared_ptr<core::KeyProvider>& keyProvider
) {
    return validateDecryptAndConvertStores({std::move(store)}, keyProvider)[0];
}

Store StoreDataSchemaMapper::toLibStore(
    const server::Store& store,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    int64_t statusCode,
    int64_t schemaVersion
) {
    return Store{
        .storeId = store.id,
        .contextId = store.contextId,
        .createDate = store.createDate,
        .creator = store.creator,
        .lastModificationDate = store.lastModificationDate,
        .lastFileDate = store.lastFileDate,
        .lastModifier = store.lastModifier,
        .users = store.users,
        .managers = store.managers,
        .version = store.version,
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .policy = core::Factory::parsePolicyServerObject(store.policy),
        .filesCount = store.files,
        .statusCode = statusCode,
        .schemaVersion = schemaVersion
    };
}
