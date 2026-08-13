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

#include <Poco/Dynamic/Var.h>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <type_traits>
#include <vector>

#include "privmx/endpoint/core/BaseModuleDataSchemaMapper.hpp"
#include "privmx/endpoint/core/ContainerKeyCache.hpp"
#include "privmx/endpoint/core/Factory.hpp"
#include "privmx/endpoint/core/UsersKeysResolver.hpp"
#include "privmx/endpoint/core/encryptors/DataSchemaMapperUtils.hpp"
#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/EndpointUtils.hpp>
#include <privmx/endpoint/core/EventMiddleware.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/endpoint/core/KeyProvider.hpp>
#include <privmx/endpoint/core/ServerTypes.hpp>
#include <privmx/endpoint/core/Types.hpp>
#include <privmx/endpoint/core/encryptors/DataEncryptorV4.hpp>
#include <privmx/utils/GuardedExecutor.hpp>
#include <privmx/utils/ThreadSaveMap.hpp>

namespace privmx {
namespace endpoint {
namespace core {

/**
 * Whether a served module struct carries key entries addressed to a group.
 *
 * Spelled as a trait rather than a `requires` expression because this header is compiled as C++17.
 */
template<typename T, typename = void>
struct module_has_group_keys : std::false_type {};
template<typename T>
struct module_has_group_keys<T, std::void_t<decltype(std::declval<T>().groupKeys)>> : std::true_type {};

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
    void initModuleDataSchemaMapper(std::shared_ptr<core::BaseModuleDataSchemaMapper> mapper) {
        _moduleDataSchemaMapper = std::move(mapper);
    }

    template<typename ModuleStruct>
    auto getAndValidateModuleCurrentEncKey(
        ModuleStruct moduleObj,
        const core::KeyProvider::GroupPrivKeyResolver& groupPrivKeyResolver = nullptr
    ) -> decltype(moduleObj.data, moduleObj.contextId, moduleObj.keys, moduleObj.resourceId, core::DecryptedEncKeyV2());
    core::DecryptedEncKeyV2 getAndValidateModuleCurrentEncKey(
        ModuleKeys moduleKeys,
        const core::KeyProvider::GroupPrivKeyResolver& groupPrivKeyResolver = nullptr
    );

    template<typename ModuleStruct>
    auto getModuleEncKeyLocation(ModuleStruct moduleObj, const std::optional<std::string>& resourceId = std::nullopt)
        -> decltype(moduleObj.contextId, core::EncKeyLocation());

    template<typename ModuleStruct>
    auto getAndValidateModuleKeys(
        ModuleStruct moduleObj,
        const std::string& resourceId,
        const core::KeyProvider::GroupPrivKeyResolver& groupPrivKeyResolver = nullptr
    ) -> decltype(moduleObj.contextId, moduleObj.keys, moduleObj.resourceId, std::unordered_map<std::string, DecryptedEncKeyV2>());

    ContainerCreateContext prepareContainerCreate(
        const std::string& contextId,
        const std::vector<UserWithPubKey>& users,
        const std::vector<UserWithPubKey>& managers
    );

    template<typename TCreateModel>
    static void fillContainerCreateModel(
        TCreateModel& model,
        const std::string& contextId,
        const std::vector<UserWithPubKey>& users,
        const std::vector<UserWithPubKey>& managers,
        const ContainerCreateContext& ctx,
        Poco::Dynamic::Var encryptedData
    ) {
        static_assert(
            std::is_base_of_v<server::ContainerCreateModelBase, TCreateModel>,
            "TCreateModel must inherit from ContainerCreateModelBase"
        );
        model.resourceId = ctx.resourceId;
        model.contextId = contextId;
        model.keyId = ctx.key.id;
        model.data = std::move(encryptedData);
        model.keys = ctx.keyEntries;
        model.users = EndpointUtils::usersWithPubKeyToIds(users);
        model.managers = EndpointUtils::usersWithPubKeyToIds(managers);
    }

    template<typename TUpdateModel>
    static void fillContainerUpdateModel(
        TUpdateModel& model,
        const std::string& id,
        const std::string& resourceId,
        const std::vector<UserWithPubKey>& users,
        const std::vector<UserWithPubKey>& managers,
        const ContainerUpdateContext& ctx,
        int64_t version,
        bool force
    ) {
        static_assert(
            std::is_base_of_v<server::ContainerUpdateModelBase, TUpdateModel>,
            "TUpdateModel must inherit from ContainerUpdateModelBase"
        );
        model.id = id;
        model.resourceId = resourceId;
        model.keyId = ctx.key.id;
        model.keys = ctx.keyEntries;
        model.users = EndpointUtils::usersWithPubKeyToIds(users);
        model.managers = EndpointUtils::usersWithPubKeyToIds(managers);
        model.version = version;
        model.force = force;
    }

    /**
     * @param distributeToUsers when false, a new key is still generated but **no per-user entries are built**.
     *
     * For a module that distributes its key some other way — a group that wraps it once to its own identity key
     * rather than once per member — building those entries is not merely redundant, it is the `O(n)` cost that
     * mechanism exists to avoid, and it would be paid in client CPU even after the entries are discarded.
     */
    template<typename TContainer, typename TEntry>
    ContainerUpdateContext prepareContainerUpdate(
        const TContainer& container,
        const TEntry& entry,
        const std::string& resourceId,
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers,
        bool forceGenerateNewKey,
        bool distributeToUsers = true,
        const core::KeyProvider::GroupPrivKeyResolver& groupPrivKeyResolver = nullptr
    ) {
        auto location{getModuleEncKeyLocation(container, resourceId)};
        auto containerKeys{getAndValidateModuleKeys(container, resourceId, groupPrivKeyResolver)};
        auto currentKey{findEncKeyByKeyId(containerKeys, entry.keyId)};
        std::string secret;
        if constexpr (std::is_same_v<std::decay_t<decltype(entry.data)>, Poco::Dynamic::Var>) {
            secret = _moduleDataSchemaMapper->decryptInternalMeta(entry.data, currentKey).secret;
        } else {
            // Inbox special Case
            secret = _moduleDataSchemaMapper->decryptInternalMeta(entry.data.toJSON(), currentKey).secret;
        }
        LOG_DEBUG("secret - ",secret)
        auto usersKeysResolver{
            core::UsersKeysResolver::create(container, users, managers, forceGenerateNewKey, currentKey)
        };
        if (!_keyProvider->verifyKeysSecret(containerKeys, location, secret)) {
            throw core::EncryptionKeyValidationException();
        }
        core::EncKey key = currentKey;
        core::DataIntegrityObject dio = _connection.getImpl()->createDIO(container.contextId, resourceId);
        std::vector<core::server::KeyEntrySet> keyEntries;
        if (usersKeysResolver->doNeedNewKey()) {
            key = _keyProvider->generateKey();
            if (distributeToUsers) {
                keyEntries =
                    _keyProvider->prepareKeysList(usersKeysResolver->getNewUsers(), key, dio, location, secret);
            }
        }
        auto usersToAddMissingKey{usersKeysResolver->getUsersToAddKey()};
        if (distributeToUsers && !usersToAddMissingKey.empty()) {
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

    std::vector<server::GroupKeyEntrySet> buildGroupKeyEntries(
        const std::vector<GroupGrantWithKey>& groups,
        const EncKey& key,
        const DataIntegrityObject& dio,
        const std::string& contextId,
        const std::string& resourceId,
        const std::string& containerSecret
    );

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
    std::shared_ptr<core::BaseModuleDataSchemaMapper> _moduleDataSchemaMapper;
    core::ContainerKeyCache _keyCache;
};

template<typename ModuleStruct>
auto ModuleBaseApi::getAndValidateModuleCurrentEncKey(
    ModuleStruct moduleObj,
    const core::KeyProvider::GroupPrivKeyResolver& groupPrivKeyResolver
) -> decltype(moduleObj.data, moduleObj.contextId, moduleObj.keys, moduleObj.resourceId, core::DecryptedEncKeyV2()) {
    auto data_entry = moduleObj.data.back();
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    auto location{getModuleEncKeyLocation(moduleObj, moduleObj.resourceId)};
    keyProviderRequest.addOne(moduleObj.keys, data_entry.keyId, location);
    if constexpr (module_has_group_keys<ModuleStruct>::value) {
        // A module may distribute its key to a *group* rather than to each member — a group wrapping its own
        // metadata key to itself does exactly that. Without this the current key is simply not found, and the
        // failure surfaces as "enc key with given keyId does not exist" rather than as anything informative.
        keyProviderRequest.addGroupKeys(moduleObj.groupKeys, location);
    }
    core::DecryptedEncKeyV2 ret =
        _keyProvider->getKeysAndVerify(keyProviderRequest, groupPrivKeyResolver).at(location).at(data_entry.keyId);
    return ret;
}

template<typename ModuleStruct>
auto ModuleBaseApi::getModuleEncKeyLocation(ModuleStruct moduleObj, const std::optional<std::string>& resourceId)
    -> decltype(moduleObj.contextId, core::EncKeyLocation()) {
    core::EncKeyLocation location{.contextId = moduleObj.contextId, .resourceId = resourceId.value_or("")};
    return location;
}

template<typename ModuleStruct>
auto ModuleBaseApi::getAndValidateModuleKeys(
    ModuleStruct moduleObj,
    const std::string& resourceId,
    const core::KeyProvider::GroupPrivKeyResolver& groupPrivKeyResolver
) -> decltype(moduleObj.contextId, moduleObj.keys, moduleObj.resourceId, std::unordered_map<std::string, DecryptedEncKeyV2>()) {
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    auto location{getModuleEncKeyLocation(moduleObj, resourceId)};
    keyProviderRequest.addAll(moduleObj.keys, location);
    if constexpr (module_has_group_keys<ModuleStruct>::value) {
        keyProviderRequest.addGroupKeys(moduleObj.groupKeys, location);
    }
    auto moduleKeys{_keyProvider->getKeysAndVerify(keyProviderRequest, groupPrivKeyResolver).at(location)};
    return moduleKeys;
}

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_THREAD_THREADAPIIMPL_HPP_
