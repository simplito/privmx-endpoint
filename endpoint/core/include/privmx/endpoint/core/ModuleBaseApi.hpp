/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_MODULEBASEAPI_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_MODULEBASEAPI_HPP_

#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <type_traits>
#include <vector>

#include "privmx/endpoint/core/ContainerKeyCache.hpp"
#include "privmx/endpoint/core/Factory.hpp"
#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/EndpointUtils.hpp>
#include <privmx/endpoint/core/EventMiddleware.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/endpoint/core/KeyProvider.hpp>
#include <privmx/endpoint/core/ServerTypes.hpp>
#include <privmx/endpoint/core/Types.hpp>
#include <privmx/endpoint/core/encryptors/DataEncryptorV4.hpp>
#include <privmx/endpoint/core/encryptors/module/ModuleDataEncryptorV4.hpp>
#include <privmx/endpoint/core/encryptors/module/ModuleDataEncryptorV5.hpp>
#include <privmx/utils/GuardedExecutor.hpp>
#include <privmx/utils/ThreadSaveMap.hpp>
#include "privmx/endpoint/core/UsersKeysResolver.hpp"
#include "privmx/endpoint/core/encryptors/DataSchemaMapperUtils.hpp"

namespace privmx {
namespace endpoint {
namespace core {

class ModuleBaseApi {
public:
    ModuleBaseApi(
        const privmx::crypto::PrivateKey& userPrivKey,
        const std::shared_ptr<core::KeyProvider>& keyProvider,
        const std::string& host,
        const std::shared_ptr<core::EventMiddleware>& eventMiddleware,
        const core::Connection& connection
    );

    virtual ~ModuleBaseApi() = default;

protected:
    template<typename ModuleStruct>
    auto decryptModuleDataV4(ModuleStruct moduleObj, const core::DecryptedEncKey& encKey)
        -> decltype(moduleObj.keyId, moduleObj.data, core::DecryptedModuleDataV4());

    template<typename ModuleStruct>
    auto decryptModuleDataV5(ModuleStruct moduleObj, const core::DecryptedEncKey& encKey)
        -> decltype(moduleObj.keyId, moduleObj.data, core::DecryptedModuleDataV5());

    template<typename ModuleStruct>
    auto extractAndDecryptModuleInternalMeta(ModuleStruct moduleObj, const core::DecryptedEncKey& encKey)
        -> decltype(moduleObj.keyId, moduleObj.data, core::ModuleInternalMetaV5());

    template<typename ModuleStruct>
    auto getAndValidateModuleCurrentEncKey(
        ModuleStruct moduleObj
    ) -> decltype(moduleObj.data, moduleObj.contextId, moduleObj.keys, moduleObj.resourceId, core::DecryptedEncKeyV2());
    core::DecryptedEncKeyV2 getAndValidateModuleCurrentEncKey(ModuleKeys moduleKeys);

    template<typename ModuleStruct>
    auto getModuleEncKeyLocation(ModuleStruct moduleObj, const std::string& resourceId)
        -> decltype(moduleObj.contextId, core::EncKeyLocation());
    template<typename ModuleStruct>
    auto getModuleEncKeyLocation(ModuleStruct moduleObj, const std::optional<std::string>& resourceIdOpt)
        -> decltype(moduleObj.contextId, core::EncKeyLocation());

    template<typename ModuleStruct>
    auto getAndValidateModuleKeys(
        ModuleStruct moduleObj,
        const std::string& resourceId
    ) -> decltype(moduleObj.contextId, moduleObj.keys, moduleObj.resourceId, std::unordered_map<std::string, DecryptedEncKeyV2>());

    template<typename TContainer, typename TEntry>
    ContainerUpdateContext prepareContainerUpdate(
        const TContainer& container,
        const TEntry& entry,
        const std::string& resourceId,
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers,
        bool forceGenerateNewKey,
        std::function<std::string(const type_identity_t<TEntry>&, const core::DecryptedEncKeyV2&)> getSecret,
        std::function<void()> throwIfInvalid
    ) {
        auto location{getModuleEncKeyLocation(container, resourceId)};
        auto containerKeys{getAndValidateModuleKeys(container, resourceId)};
        auto currentKey{findEncKeyByKeyId(containerKeys, entry.keyId)};
        std::string secret = getSecret(entry, currentKey);
        auto usersKeysResolver{
            core::UsersKeysResolver::create(container, users, managers, forceGenerateNewKey, currentKey)
        };
        if (!_keyProvider->verifyKeysSecret(containerKeys, location, secret)) {
            throwIfInvalid();
        }
        core::EncKey key = currentKey;
        core::DataIntegrityObject dio = _connection.getImpl()->createDIO(container.contextId, resourceId);
        std::vector<core::server::KeyEntrySet> keyEntries;
        if (usersKeysResolver->doNeedNewKey()) {
            key = _keyProvider->generateKey();
            keyEntries = _keyProvider->prepareKeysList(
                usersKeysResolver->getNewUsers(), key, dio, location, secret
            );
        }
        auto usersToAddMissingKey{usersKeysResolver->getUsersToAddKey()};
        if (!usersToAddMissingKey.empty()) {
            auto tmp = _keyProvider->prepareMissingKeysForNewUsers(
                containerKeys, usersToAddMissingKey, dio, location, secret
            );
            keyEntries.insert(keyEntries.end(), tmp.begin(), tmp.end());
        }
        return {location, key, dio, secret, keyEntries};
    }

    template<typename TReturn>
    TReturn withKeyRefresh(
        const std::string& moduleId,
        int64_t invalidKeyCode,
        std::function<TReturn(const core::ModuleKeys&)> op
    ) {
        try {
            return op(getModuleKeys(moduleId));
        } catch (const privmx::utils::PrivmxException& e) {
            if (core::ExceptionConverter::convert(e).getCode() == invalidKeyCode) {
                return op(getNewModuleKeysAndUpdateCache(moduleId));
            }
            throw;
        }
    }

    DecryptedEncKeyV2 findEncKeyByKeyId(
        std::unordered_map<std::string, DecryptedEncKeyV2> keys,
        const std::string& keyId
    );

    ModuleKeys getModuleKeys(
        const std::string& moduleId,
        const std::optional<std::set<std::string>>& keyIds = std::nullopt,
        const std::optional<int64_t>& minimumSchemaVersion = std::nullopt
    );
    ModuleKeys getModuleKeysForItem(
        const std::string& moduleId,
        const std::string& keyId,
        std::optional<int64_t> minimumSchemaVersion = std::nullopt
    ) {
        return getModuleKeys(moduleId, std::set<std::string>{keyId}, minimumSchemaVersion);
    }
    virtual std::pair<ModuleKeys, int64_t> getModuleKeysAndVersionFromServer(std::string moduleId) = 0;
    ModuleKeys getNewModuleKeysAndUpdateCache(const std::string& moduleId);
    void setNewModuleKeysInCache(const std::string& moduleId, const ModuleKeys& newKeys, int64_t moduleVersion);
    void invalidateModuleKeysInCache(const std::optional<std::string>& moduleId = std::nullopt);

    std::shared_ptr<privmx::utils::GuardedExecutor> _guardedExecutor;

private:
    static core::ContainerKeyCache::CachedModuleKeys convertModuleKeysToContainerKeyCacheFormat(
        const ModuleKeys& moduleKeys,
        int64_t moduleVersion
    );
    static ModuleKeys convertContainerKeyCacheModuleKeysToModuleApiFormat(
        const core::ContainerKeyCache::CachedModuleKeys& moduleKeys
    );

    privmx::crypto::PrivateKey _userPrivKey;
    std::shared_ptr<core::KeyProvider> _keyProvider;
    std::string _host;
    std::shared_ptr<core::EventMiddleware> _eventMiddleware;
    core::Connection _connection;
    core::ModuleDataEncryptorV4 _moduleDataEncryptorV4;
    core::ModuleDataEncryptorV5 _moduleDataEncryptorV5;
    core::ContainerKeyCache _keyCache;
};

template<typename ModuleStruct>
auto ModuleBaseApi::decryptModuleDataV4(ModuleStruct moduleObj, const core::DecryptedEncKey& encKey)
    -> decltype(moduleObj.keyId, moduleObj.data, core::DecryptedModuleDataV4()) {
    try {
        auto encryptedData = core::dynamic::EncryptedModuleDataV4::fromJSON(moduleObj.data);
        return _moduleDataEncryptorV4.decrypt(encryptedData, encKey.key);
    } catch (const core::Exception& e) {
        return core::DecryptedModuleDataV4{
            {.dataStructureVersion = core::ModuleDataSchema::Version::VERSION_4, .statusCode = e.getCode()},
            {},
            {},
            {},
            {}
        };
    } catch (const privmx::utils::PrivmxException& e) {
        return core::DecryptedModuleDataV4{
            {.dataStructureVersion = core::ModuleDataSchema::Version::VERSION_4,
             .statusCode = core::ExceptionConverter::convert(e).getCode()},
            {},
            {},
            {},
            {}
        };
    } catch (...) {
        return core::DecryptedModuleDataV4{
            {.dataStructureVersion = core::ModuleDataSchema::Version::VERSION_4,
             .statusCode = ENDPOINT_CORE_EXCEPTION_CODE},
            {},
            {},
            {},
            {}
        };
    }
}

template<typename ModuleStruct>
auto ModuleBaseApi::decryptModuleDataV5(ModuleStruct moduleObj, const core::DecryptedEncKey& encKey)
    -> decltype(moduleObj.keyId, moduleObj.data, core::DecryptedModuleDataV5()) {
    try {
        auto encryptedData = core::dynamic::EncryptedModuleDataV5::fromJSON(moduleObj.data);
        if (encKey.statusCode != 0) {
            auto tmp = _moduleDataEncryptorV5.extractPublic(encryptedData);
            tmp.statusCode = encKey.statusCode;
            return tmp;
        }
        return _moduleDataEncryptorV5.decrypt(encryptedData, encKey.key);
    } catch (const core::Exception& e) {
        return core::DecryptedModuleDataV5{
            {.dataStructureVersion = core::ModuleDataSchema::Version::VERSION_5, .statusCode = e.getCode()},
            {},
            {},
            {},
            {},
            {}
        };
    } catch (const privmx::utils::PrivmxException& e) {
        return core::DecryptedModuleDataV5{
            {.dataStructureVersion = core::ModuleDataSchema::Version::VERSION_5,
             .statusCode = core::ExceptionConverter::convert(e).getCode()},
            {},
            {},
            {},
            {},
            {}
        };
    } catch (...) {
        return core::DecryptedModuleDataV5{
            {.dataStructureVersion = core::ModuleDataSchema::Version::VERSION_5,
             .statusCode = ENDPOINT_CORE_EXCEPTION_CODE},
            {},
            {},
            {},
            {},
            {}
        };
    }
}

template<typename ModuleStruct>
auto ModuleBaseApi::extractAndDecryptModuleInternalMeta(ModuleStruct moduleObj, const core::DecryptedEncKey& encKey)
    -> decltype(moduleObj.keyId, moduleObj.data, core::ModuleInternalMetaV5()) {
    auto versioned = core::dynamic::VersionedData::fromJSON(moduleObj.data);
    switch (versioned.version) {
    case core::ModuleDataSchema::Version::UNKNOWN:
        return core::ModuleInternalMetaV5();
    case core::ModuleDataSchema::Version::VERSION_4:
        return core::ModuleInternalMetaV5();
    case core::ModuleDataSchema::Version::VERSION_5:
        return decryptModuleDataV5(moduleObj, encKey).internalMeta;
    default:
        return core::ModuleInternalMetaV5();
    }
}

template<typename ModuleStruct>
auto ModuleBaseApi::getAndValidateModuleCurrentEncKey(ModuleStruct moduleObj)
    -> decltype(moduleObj.data, moduleObj.contextId, moduleObj.keys, moduleObj.resourceId, core::DecryptedEncKeyV2()) {
    auto data_entry = moduleObj.data.back();
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    auto location{getModuleEncKeyLocation(moduleObj, moduleObj.resourceId)};
    keyProviderRequest.addOne(moduleObj.keys, data_entry.keyId, location);
    core::DecryptedEncKeyV2 ret = _keyProvider->getKeysAndVerify(keyProviderRequest).at(location).at(data_entry.keyId);
    return ret;
}

template<typename ModuleStruct>
auto ModuleBaseApi::getModuleEncKeyLocation(ModuleStruct moduleObj, const std::string& resourceId)
    -> decltype(moduleObj.contextId, core::EncKeyLocation()) {
    core::EncKeyLocation location{.contextId = moduleObj.contextId, .resourceId = resourceId};
    return location;
}

template<typename ModuleStruct>
auto ModuleBaseApi::getModuleEncKeyLocation(ModuleStruct moduleObj, const std::optional<std::string>& resourceIdOpt)
    -> decltype(moduleObj.contextId, core::EncKeyLocation()) {
    core::EncKeyLocation location{.contextId = moduleObj.contextId, .resourceId = resourceIdOpt.value_or("")};
    return location;
}

template<typename ModuleStruct>
auto ModuleBaseApi::getAndValidateModuleKeys(
    ModuleStruct moduleObj,
    const std::string& resourceId
) -> decltype(moduleObj.contextId, moduleObj.keys, moduleObj.resourceId, std::unordered_map<std::string, DecryptedEncKeyV2>()) {
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    auto location{getModuleEncKeyLocation(moduleObj, resourceId)};
    keyProviderRequest.addAll(moduleObj.keys, location);
    auto moduleKeys{_keyProvider->getKeysAndVerify(keyProviderRequest).at(location)};
    return moduleKeys;
}

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_THREAD_THREADAPIIMPL_HPP_
