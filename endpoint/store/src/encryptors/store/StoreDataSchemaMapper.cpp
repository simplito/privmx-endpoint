/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/store/encryptors/store/StoreDataSchemaMapper.hpp"

#include <Poco/JSON/Object.h>
#include <privmx/endpoint/core/Factory.hpp>
#include <privmx/endpoint/core/encryptors/DataSchemaMapperUtils.hpp>

#include "privmx/endpoint/store/StoreException.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::store;

StoreDataSchemaMapper::StoreDataSchemaMapper(
    const privmx::crypto::PrivateKey& userPrivKey,
    const core::Connection& connection
)
    : core::BaseModuleDataSchemaMapper(userPrivKey, connection) {
    _strategyV4 = std::make_shared<StoreDataSchemaStrategyV4>();
    _strategyMapper.registerStrategy(core::ModuleDataSchema::Version::VERSION_4, _strategyV4);
    _strategyV5 = std::make_shared<StoreDataSchemaStrategyV5>();
    _strategyMapper.registerStrategy(core::ModuleDataSchema::Version::VERSION_5, _strategyV5);
}

Poco::Dynamic::Var StoreDataSchemaMapper::encrypt(const core::ModuleDataToEncryptV5& data, const std::string& key) {
    return _strategyV5->encrypt(data, _userPrivKey, key).toJSON();
}

std::tuple<Store, core::DataIntegrityObject> StoreDataSchemaMapper::decrypt(
    const server::Store& store,
    const core::DecryptedEncKey& encKey
) {
    return _strategyMapper.dispatch(
        static_cast<int64_t>(getDataStructureVersion(store.data.back())), store, encKey,
        [&]() -> std::tuple<Store, core::DataIntegrityObject> {
            return {
                toLibStore(store, {}, {}, UnknowStoreFormatException().getCode(), StoreDataSchema::Version::UNKNOWN), {}
            };
        }
    );
}

void StoreDataSchemaMapper::assertDataIntegrity(const server::Store& store) {
    const auto& entry = store.data.back();
    switch (getDataStructureVersion(entry)) {
    case core::ModuleDataSchema::Version::UNKNOWN:
        throw UnknowStoreFormatException();
    case core::ModuleDataSchema::Version::VERSION_4:
        return;
    case core::ModuleDataSchema::Version::VERSION_5: {
        core::DataSchemaMapperUtils::assertContainerV5DIOIntegrity(entry.data, store, _strategyV5, [] {
            throw StoreDataIntegrityException();
        });
        return;
    }
    default:
        throw UnknowStoreFormatException();
    }
}

uint32_t StoreDataSchemaMapper::validateDataIntegrity(const server::Store& store) {
    return core::DataSchemaMapperUtils::toStatusCode([&] { assertDataIntegrity(store); });
}

std::vector<Store> StoreDataSchemaMapper::validateDecryptAndConvertStores(
    const std::vector<server::Store>& stores,
    const std::shared_ptr<core::KeyProvider>& keyProvider
) {
    return core::DataSchemaMapperUtils::batchValidateDecryptVerifyContainers<Store>(
        stores, keyProvider, _connection, [&](const server::Store& s) { return validateDataIntegrity(s); },
        [](const server::Store& s) -> core::EncKeyLocation {
            return {.contextId = s.contextId, .resourceId = s.resourceId.value_or("")};
        },
        [&](const server::Store& s, const core::DecryptedEncKey& key) { return decrypt(s, key); },
        [](const server::Store& s, uint32_t code) {
            return toLibStore(s, {}, {}, code, StoreDataSchema::Version::UNKNOWN);
        }
    );
}

Store StoreDataSchemaMapper::validateDecryptAndConvertStore(
    const server::Store& store,
    const std::shared_ptr<core::KeyProvider>& keyProvider
) {
    return validateDecryptAndConvertStores({store}, keyProvider)[0];
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
