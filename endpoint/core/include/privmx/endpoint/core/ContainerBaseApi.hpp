/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_CONTAINERBASEAPI_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_CONTAINERBASEAPI_HPP_

#include <Poco/Dynamic/Var.h>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <vector>

#include "privmx/endpoint/core/BaseModuleDataSchemaMapper.hpp"
#include "privmx/endpoint/core/ContainerKeyCache.hpp"
#include "privmx/endpoint/core/Factory.hpp"
#include "privmx/endpoint/core/UsersKeysResolver.hpp"
#include "privmx/endpoint/core/encryptors/DataSchemaMapperUtils.hpp"
#include "privmx/utils/Logger.hpp"
#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/ConvertedExceptions.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
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

// Whether a served module struct carries key entries addressed to a group.
// Spelled as a trait rather than a `requires` expression because this header is compiled as C++17.
template<typename T, typename = void>
struct module_has_group_keys : std::false_type {};
template<typename T>
struct module_has_group_keys<T, std::void_t<decltype(std::declval<T>().groupKeys)>> : std::true_type {};

// Whether a served module struct carries per-member key entries at all. A group carries none: its metadata key
// is wrapped once to its own grant public key, so the field is absent from what the bridge serves.
template<typename T, typename = void>
struct module_has_keys : std::false_type {};
template<typename T>
struct module_has_keys<T, std::void_t<decltype(std::declval<T>().keys)>> : std::true_type {};

// The container machinery every module shares, groups included: the key cache, the roster, and the key
// preparation around a create or an update. Group grants live one layer up, in `group::GroupAwareModuleApi`.
class ContainerBaseApi {
public:
    ContainerBaseApi(
        const privmx::crypto::PrivateKey& userPrivKey,
        const std::shared_ptr<core::KeyProvider>& keyProvider,
        const std::string& host,
        const std::shared_ptr<core::EventMiddleware>& eventMiddleware,
        const core::Connection& connection
    );

    virtual ~ContainerBaseApi() = default;

protected:
    void initModuleDataSchemaMapper(std::shared_ptr<core::BaseModuleDataSchemaMapper> mapper) {
        _moduleDataSchemaMapper = std::move(mapper);
    }

    // Opens keys wrapped to a group's grant key. Core cannot reach the group module, so the resolver is handed
    // in: by `GroupAwareModuleApi` for a container, by the group itself for its own tree.
    void initGroupPrivKeyResolver(const core::KeyProvider::GroupPrivKeyResolver& resolver);

    template<typename ModuleStruct>
    auto getAndValidateModuleCurrentEncKey(ModuleStruct moduleObj)
        -> decltype(moduleObj.data, moduleObj.contextId, moduleObj.resourceId, core::DecryptedEncKeyV2());
    core::DecryptedEncKeyV2 getAndValidateModuleCurrentEncKey(ModuleKeys moduleKeys);

    template<typename ModuleStruct>
    auto getModuleEncKeyLocation(ModuleStruct moduleObj, const std::optional<std::string>& resourceId = std::nullopt)
        -> decltype(moduleObj.contextId, core::EncKeyLocation());

    template<typename ModuleStruct>
    auto getAndValidateModuleKeys(ModuleStruct moduleObj, const std::string& resourceId)
        -> decltype(moduleObj.contextId, moduleObj.resourceId, std::unordered_map<std::string, DecryptedEncKeyV2>());

    struct ContainerRoster {
        std::vector<UserWithPubKey> users;
        std::vector<UserWithPubKey> managers;
    };

    // A container carries its members as bare user ids, but re-wrapping its key needs a public key per member,
    // and the Context user list is where those live. Throws if a member has left it.
    ContainerRoster resolveRosterPubKeys(
        const std::string& contextId,
        const std::vector<std::string>& userIds,
        const std::vector<std::string>& managerIds
    );

    // Empty rosters build no per-user key entries — for a module that hands its key over some other way.
    ContainerCreateContext prepareContainerCreate(
        const std::string& contextId,
        const std::vector<UserWithPubKey>& users,
        const std::vector<UserWithPubKey>& managers
    );

    template<typename TContainer, typename TEntry>
    ContainerUpdateContext prepareContainerUpdate(
        const TContainer& container,
        const TEntry& entry,
        const std::string& resourceId,
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers,
        bool forceGenerateNewKey
    ) {
        auto plan = planContainerUpdate(container, entry, resourceId, users, managers, forceGenerateNewKey);
        plan.ctx.keyEntries = buildRosterKeyEntries(plan);
        return plan.ctx;
    }

    // The same preparation for a container whose key never reaches members as a per-member entry: a group wraps
    // its metadata key once to its own grant public key and members open it by climbing the key tree.
    template<typename TContainer, typename TEntry>
    ContainerUpdateContext prepareContainerUpdateWithoutKeyEntries(
        const TContainer& container,
        const TEntry& entry,
        const std::string& resourceId,
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers,
        bool forceGenerateNewKey
    ) {
        return planContainerUpdate(container, entry, resourceId, users, managers, forceGenerateNewKey).ctx;
    }

    // The served container struct reduced to what the key cache and the decryptors need. Identical for every
    // container type — the schema version comes from the module's own mapper, which the base already holds.
    template<typename TContainer>
    ModuleKeys containerToModuleKeys(const TContainer& container) {
        static_assert(
            std::is_base_of_v<server::ContainerInfoBase, TContainer>,
            "TContainer must inherit from ContainerInfoBase"
        );
        return ModuleKeys{
            .keys = container.keys,
            .groupKeys = container.groupKeys,
            .staleGroups = container.staleGroups,
            .currentKeyId = container.keyId,
            .moduleSchemaVersion = _moduleDataSchemaMapper->getDataStructureVersion(container.data.back()),
            .moduleResourceId = container.resourceId.value_or(""),
            .contextId = container.contextId
        };
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

    // Seals a module key to each grantee group's public key. Lives here rather than with the rest of the grant
    // machinery because a group uses it on itself, to wrap its own metadata key to its own grant key.
    std::vector<server::GroupKeyEntrySet> buildGroupKeyEntries(
        const std::vector<GroupGrantWithKey>& groups,
        const EncKey& key,
        const DataIntegrityObject& dio,
        const std::string& contextId,
        const std::string& resourceId,
        const std::string& containerSecret
    );

    static bool isRekeyNeeded(const server::ContainerInfoBase& container) { return !container.staleGroups.empty(); }
    static bool isRekeyNeeded(const ModuleKeys& moduleKeys) { return !moduleKeys.staleGroups.empty(); }

    // Refuses a key that is stale — see `ModuleKeys::staleGroups`. Called where the answer decides whether to
    // encrypt; the container update and re-key calls are deliberately not guarded, a re-key being the way out.
    static void assertRekeyNotNeeded(const server::ContainerInfoBase& container);
    static void assertRekeyNotNeeded(const ModuleKeys& moduleKeys);

    std::shared_ptr<privmx::utils::GuardedExecutor> _guardedExecutor;
    core::KeyProvider::GroupPrivKeyResolver _groupPrivKeyResolver;

private:
    // Everything an update needs decided before any key entry is built, so a module that distributes its key
    // some other way stops here.
    struct ContainerUpdatePlan {
        ContainerUpdateContext ctx;
        std::unordered_map<std::string, DecryptedEncKeyV2> containerKeys;
        std::shared_ptr<UsersKeysResolver> roster;
        bool needNewKey;
    };

    template<typename TContainer, typename TEntry>
    ContainerUpdatePlan planContainerUpdate(
        const TContainer& container,
        const TEntry& entry,
        const std::string& resourceId,
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers,
        bool forceGenerateNewKey
    );

    std::vector<server::KeyEntrySet> buildRosterKeyEntries(const ContainerUpdatePlan& plan);

    static void assertNoStaleGroups(const std::vector<std::string>& staleGroups);

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
auto ContainerBaseApi::getAndValidateModuleCurrentEncKey(ModuleStruct moduleObj)
    -> decltype(moduleObj.data, moduleObj.contextId, moduleObj.resourceId, core::DecryptedEncKeyV2()) {
    auto data_entry = moduleObj.data.back();
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    auto location{getModuleEncKeyLocation(moduleObj, moduleObj.resourceId)};
    if constexpr (module_has_keys<ModuleStruct>::value) {
        keyProviderRequest.addOne(moduleObj.keys, data_entry.keyId, location);
    }
    if constexpr (module_has_group_keys<ModuleStruct>::value) {
        keyProviderRequest.addGroupKeys(moduleObj.groupKeys, location);
    }
    auto keysMap = _keyProvider->getKeysAndVerify(keyProviderRequest, _groupPrivKeyResolver);
    core::DecryptedEncKeyV2 ret = keysMap.at(location).at(data_entry.keyId);
    return ret;
}

template<typename ModuleStruct>
auto ContainerBaseApi::getModuleEncKeyLocation(ModuleStruct moduleObj, const std::optional<std::string>& resourceId)
    -> decltype(moduleObj.contextId, core::EncKeyLocation()) {
    core::EncKeyLocation location{.contextId = moduleObj.contextId, .resourceId = resourceId.value_or("")};
    return location;
}

template<typename ModuleStruct>
auto ContainerBaseApi::getAndValidateModuleKeys(ModuleStruct moduleObj, const std::string& resourceId)
    -> decltype(moduleObj.contextId, moduleObj.resourceId, std::unordered_map<std::string, DecryptedEncKeyV2>()) {
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    auto location{getModuleEncKeyLocation(moduleObj, resourceId)};
    if constexpr (module_has_keys<ModuleStruct>::value) {
        keyProviderRequest.addAll(moduleObj.keys, location);
    }
    if constexpr (module_has_group_keys<ModuleStruct>::value) {
        keyProviderRequest.addGroupKeys(moduleObj.groupKeys, location);
    }
    auto moduleKeys{_keyProvider->getKeysAndVerify(keyProviderRequest, _groupPrivKeyResolver).at(location)};
    return moduleKeys;
}

template<typename TContainer, typename TEntry>
ContainerBaseApi::ContainerUpdatePlan ContainerBaseApi::planContainerUpdate(
    const TContainer& container,
    const TEntry& entry,
    const std::string& resourceId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    bool forceGenerateNewKey
) {
    auto location{getModuleEncKeyLocation(container, resourceId)};
    auto containerKeys{getAndValidateModuleKeys(container, resourceId)};
    auto currentKey{findEncKeyByKeyId(containerKeys, entry.keyId)};
    std::string secret;
    if constexpr (std::is_same_v<std::decay_t<decltype(entry.data)>, Poco::Dynamic::Var>) {
        secret = _moduleDataSchemaMapper->decryptInternalMeta(entry.data, currentKey).secret;
    } else {
        // Inbox special Case
        secret = _moduleDataSchemaMapper->decryptInternalMeta(entry.data.toJSON(), currentKey).secret;
    }
    LOG_DEBUG("secret - ", secret)
    auto roster{core::UsersKeysResolver::create(container, users, managers, forceGenerateNewKey, currentKey)};
    if (!_keyProvider->verifyKeysSecret(containerKeys, location, secret)) {
        throw core::EncryptionKeyValidationException();
    }
    core::EncKey key = currentKey;
    core::DataIntegrityObject dio = _connection.getImpl()->createDIO(container.contextId, resourceId);
    bool needNewKey = roster->doNeedNewKey();
    if (needNewKey) {
        key = _keyProvider->generateKey();
    }
    return ContainerUpdatePlan{
        .ctx = {.location = location, .key = key, .dio = dio, .secret = secret, .keyEntries = {}},
        .containerKeys = containerKeys,
        .roster = roster,
        .needNewKey = needNewKey
    };
}

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_CONTAINERBASEAPI_HPP_
