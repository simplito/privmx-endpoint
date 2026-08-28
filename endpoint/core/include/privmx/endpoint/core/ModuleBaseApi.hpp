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
#include <algorithm>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <vector>

#include "privmx/endpoint/core/BaseModuleDataSchemaMapper.hpp"
#include "privmx/endpoint/core/ContainerKeyCache.hpp"
#include "privmx/endpoint/core/Factory.hpp"
#include "privmx/endpoint/core/UsersKeysResolver.hpp"
#include "privmx/endpoint/core/encryptors/DataSchemaMapperUtils.hpp"
#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/EndpointUtils.hpp>
#include <privmx/endpoint/core/EventMiddleware.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/endpoint/core/ConvertedExceptions.hpp>
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

/**
 * Whether a served module struct carries per-member key entries at all.
 *
 * A group carries none: its metadata key is wrapped once to its own grant public key and members open it by
 * climbing the key tree, so the field is absent from what the bridge serves rather than merely empty.
 */
template<typename T, typename = void>
struct module_has_keys : std::false_type {};
template<typename T>
struct module_has_keys<T, std::void_t<decltype(std::declval<T>().keys)>> : std::true_type {};

class ModuleBaseApi {
public:
    using GroupEpochResolver = std::function<std::unordered_map<std::string, GroupEpochInfo>(
        const std::string& contextId,
        const std::vector<std::string>& groupIds
    )>;

    struct GroupResolvers {
        core::KeyProvider::GroupPrivKeyResolver groupPrivKey;
        GroupEpochResolver groupEpochs;
    };

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

    /**
     * Wires up group key resolution. Takes an optional so a module can hand over whatever its own group module
     * produced without branching — `std::nullopt` (no GroupApi given) leaves the module group-unaware.
     * Core cannot reach into the group module, so building the resolvers stays on the group side.
     */
    void initGroupResolvers(const std::optional<GroupResolvers>& resolvers);

    template<typename ModuleStruct>
    auto getAndValidateModuleCurrentEncKey(
        ModuleStruct moduleObj,
        const core::KeyProvider::GroupPrivKeyResolver& groupPrivKeyResolver = nullptr
    ) -> decltype(moduleObj.data, moduleObj.contextId, moduleObj.resourceId, core::DecryptedEncKeyV2());
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
    ) -> decltype(moduleObj.contextId, moduleObj.resourceId, std::unordered_map<std::string, DecryptedEncKeyV2>());

    struct ContainerRoster {
        std::vector<UserWithPubKey> users;
        std::vector<UserWithPubKey> managers;
    };

    /**
     * Puts a public key to each name on a served container's roster.
     *
     * A container carries its members as bare user ids, but re-wrapping its key needs a public key per member.
     * Applications supply those themselves; a re-key the library starts on its own has to find them, and the
     * Context user list is where they live. Both rosters at once, because that listing is a round trip and a
     * container's users and managers always come from the same Context. Throws if a member has left it.
     */
    ContainerRoster resolveRosterPubKeys(
        const std::string& contextId,
        const std::vector<std::string>& userIds,
        const std::vector<std::string>& managerIds
    );

    /**
     * Runs a re-key the library started on its own, absorbing the two outcomes that are not failures.
     *
     * A lost race (`ContainerRotatedAlreadyException`) means somebody else already did the work, so the cached
     * keys are dropped and the caller carries on. A refusal (`AccessDeniedException`) means this caller may write
     * but may not re-key, which is the one case an automatic re-key cannot paper over: it becomes the
     * `StaleKeyRekeyRequiredException` such a caller would have been given before any of this existed, rather
     * than an access error for a call they never made. Anything else is a real failure and is rethrown.
     *
     * `UnresolvedGroupGranteeException` is deliberately among those: a caller who belongs to none of the
     * container's grantee groups cannot read their epoch keys and so cannot re-key at all (see the module's
     * public `rotate*Keys` docs). It names the group, which is more use than a generic "somebody must re-key".
     */
    void runAutoRekey(const std::string& moduleId, const std::function<void()>& rotate);

    /** Empty rosters build no per-user key entries — for a module that hands its key over some other way. */
    ContainerCreateContext prepareContainerCreate(
        const std::string& contextId,
        const std::vector<UserWithPubKey>& users,
        const std::vector<UserWithPubKey>& managers
    );

    template<typename TCreateModel>
    void fillContainerCreateModel(
        TCreateModel& model,
        const std::string& contextId,
        const std::vector<UserWithPubKey>& users,
        const std::vector<UserWithPubKey>& managers,
        const ContainerCreateContext& ctx,
        Poco::Dynamic::Var encryptedData,
        const std::optional<std::vector<GroupGrantWithKey>>& groups = std::nullopt
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
        if (groups.has_value() && !groups->empty()) {
            fillContainerGroupGrants(model, contextId, ctx.resourceId, ctx.key, ctx.dio, ctx.secret, groups.value());
        }
    }

    template<typename TUpdateModel>
    void fillContainerUpdateModel(
        TUpdateModel& model,
        const std::string& id,
        const std::string& resourceId,
        const std::vector<UserWithPubKey>& users,
        const std::vector<UserWithPubKey>& managers,
        const ContainerUpdateContext& ctx,
        int64_t version,
        bool force,
        const std::optional<std::vector<GroupGrantWithKey>>& groups = std::nullopt
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
        if (groups.has_value()) {
            fillContainerGroupGrants(
                model, ctx.location.contextId, resourceId, ctx.key, ctx.dio, ctx.secret, groups.value()
            );
        }
    }

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
        LOG_DEBUG("secret - ", secret)
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
                keyEntries = _keyProvider->prepareKeysList(
                    usersKeysResolver->getNewUsers(), key, dio, location, secret
                );
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

    /**
     * Runs an item write against the module's current keys, retrying once if the key turns out to be spent.
     *
     * `autoRekey`, when given, makes a stale key (see `ModuleKeys::staleGroups`) recoverable instead of fatal:
     * the module re-keys the container and the write is retried against the new key. Left null — the default —
     * a stale key still reaches `assertRekeyNotNeeded` and surfaces as `StaleKeyRekeyRequiredException`.
     */
    template<typename TReturn>
    TReturn withKeyRefresh(
        const std::string& moduleId,
        int64_t invalidKeyCode,
        std::function<TReturn(const core::ModuleKeys&)> op,
        const std::function<void()>& autoRekey = nullptr
    ) {
        auto keys = getModuleKeys(moduleId);
        // Proactive: the keys we already hold say the container is stale, so the write is doomed — re-key now
        // rather than spending a round trip being told so.
        if (autoRekey && isRekeyNeeded(keys)) {
            autoRekey();
            keys = getNewModuleKeysAndUpdateCache(moduleId);
        }
        try {
            return op(keys);
        } catch (const privmx::utils::PrivmxException& e) {
            auto code = core::ExceptionConverter::convert(e).getCode();
            if (code == invalidKeyCode) {
                return op(getNewModuleKeysAndUpdateCache(moduleId));
            }
            // Reactive, and the only reliable trigger: a cached `staleGroups` is a snapshot that nothing
            // invalidates when a grantee group's epoch advances (see ContainerKeyCache), so the check above can
            // be arbitrarily out of date. The bridge's refusal cannot be.
            if (autoRekey && code == privmx::endpoint::server::ContainerGroupEpochOutdatedException().getCode()) {
                autoRekey();
                return op(getNewModuleKeysAndUpdateCache(moduleId));
            }
            throw;
        }
        // One retry only: a group that advances its epoch again mid-flight gives the caller a real error rather
        // than a spin.
    }

    /**
     * The served container struct reduced to what the key cache and the decryptors need. Identical for every
     * container type — the schema version comes from the module's own mapper, which the base already holds.
     */
    template<typename TContainer>
    auto containerToModuleKeys(const TContainer& container)
        -> decltype(container.keys, container.groupKeys, container.staleGroups, container.keyId, ModuleKeys()) {
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

    std::vector<server::GroupKeyEntrySet> buildGroupKeyEntries(
        const std::vector<GroupGrantWithKey>& groups,
        const EncKey& key,
        const DataIntegrityObject& dio,
        const std::string& contextId,
        const std::string& resourceId,
        const std::string& containerSecret
    );

    template<typename TContainer>
    static auto isRekeyNeeded(const TContainer& container) -> decltype(container.staleGroups, bool()) {
        return !container.staleGroups.empty();
    }

    /**
     * Refuses a key that is stale — see `ModuleKeys::staleGroups`. Called where the answer decides whether to
     * encrypt; the container update and re-key calls are deliberately not guarded, a re-key being the way out.
     */
    template<typename TContainer>
    static auto assertRekeyNotNeeded(const TContainer& container) -> decltype(container.staleGroups, void()) {
        if (isRekeyNeeded(container)) {
            std::string staleGroups;
            for (const auto& groupId : container.staleGroups) {
                staleGroups += staleGroups.empty() ? groupId : "," + groupId;
            }
            throw StaleKeyRekeyRequiredException("staleGroups=" + staleGroups);
        }
    }

    template<typename TContainer>
    static auto doesGroupStateForceNewKey(const TContainer& container, const std::vector<GroupGrantWithKey>& groups)
        -> decltype(container.groups, container.staleGroups, bool()) {
        for (const auto& current : container.groups) {
            auto kept = std::find_if(groups.begin(), groups.end(), [&](const GroupGrantWithKey& g) {
                return g.groupId == current.groupId;
            });
            if (kept == groups.end()) {
                return true;
            }
        }
        return !groups.empty() && isRekeyNeeded(container);
    }

    template<typename TContainer>
    auto resolveGranteesForRekey(const TContainer& container, const std::vector<GroupGrantWithKey>& callerSupplied)
        -> decltype(container.groups, container.contextId, std::vector<GroupGrantWithKey>()) {
        std::vector<GroupGrantWithKey> grants;
        grants.reserve(container.groups.size());
        for (const auto& grant : container.groups) {
            auto supplied = std::find_if(callerSupplied.begin(), callerSupplied.end(), [&](const GroupGrantWithKey& g) {
                return g.groupId == grant.groupId;
            });
            if (supplied != callerSupplied.end()) {
                // The caller's public key wins where it has one: it is the key it verified out-of-band, and the
                // role still comes from the grant, which a re-key cannot change.
                grants.push_back(
                    GroupGrantWithKey{
                        .groupId = grant.groupId,
                        .role = grant.role,
                        .groupPubKey = supplied->groupPubKey,
                        .groupEpoch = supplied->groupEpoch
                    }
                );
            } else {
                grants.push_back(GroupGrantWithKey{.groupId = grant.groupId, .role = grant.role});
            }
        }
        for (const auto& g : callerSupplied) {
            auto granted = std::find_if(
                container.groups.begin(), container.groups.end(),
                [&](const server::GroupGrant& grant) { return grant.groupId == g.groupId; }
            );
            if (granted == container.groups.end()) {
                // Not dropped silently: a re-key cannot add a grant (the bridge refuses a key entry for a group
                // the container does not grant), so a group named here that the container does not grant is a
                // caller mistake that the container's update call, not this one, is the fix for.
                LOG_DEBUG("[resolveGranteesForRekey] group ", g.groupId, " is not a grantee of this module — ignored")
            }
        }
        std::unordered_map<std::string, GroupEpochInfo> groupCache;
        resolveGroupEpochs(container.contextId, grants, groupCache);
        return grants;
    }

    /**
     * Re-encrypts a container's key for its current members and grantee groups, changing nothing else.
     *
     * The caller fetches the container (each module has its own get model) and supplies `sendRotateRequest`,
     * which issues the module's own rotate RPC. Everything between is identical for every container type.
     */
    template<typename TRotateModel, typename TContainer, typename TSendRotateRequest>
    void rotateContainerKeys(
        const std::string& id,
        const TContainer& container,
        const std::vector<UserWithPubKey>& users,
        const std::vector<UserWithPubKey>& managers,
        int64_t version,
        bool force,
        const std::vector<GroupGrantWithKey>& groups,
        TSendRotateRequest&& sendRotateRequest
    ) {
        static_assert(
            std::is_base_of_v<server::ContainerRotateKeysModelBase, TRotateModel>,
            "TRotateModel must inherit from ContainerRotateKeysModelBase"
        );
        const auto& currentEntry = container.data.back();
        auto resourceId = container.resourceId.value_or(EndpointUtils::generateId());
        auto ctx = prepareContainerUpdate(
            container, currentEntry, resourceId, users, managers, true, true, _groupPrivKeyResolver
        );

        TRotateModel model;
        model.id = id;
        model.keyId = ctx.key.id;
        model.keys = ctx.keyEntries;
        model.version = version;
        model.force = force;

        // A re-key changes no grants, so the grantees are the container's own — `container.groups`, which the bridge
        // serves in full. Taking them from `groups` instead would silently drop every grantee the caller did not
        // name, and a caller can only name the groups it belongs to: `groupKeys`, the one place a container's
        // grantee groups show up in its payload, is narrowed to those. The bridge rejects a re-key that leaves a
        // granted group without an entry at the new keyId, so the dropped grantees would fail the whole call.
        model.groupKeys = buildRekeyGroupKeyEntries(container, resourceId, ctx, groups);

        sendRotateRequest(model);
        invalidateModuleKeysInCache(id);
    }

    template<typename TContainer>
    auto buildRekeyGroupKeyEntries(
        const TContainer& container,
        const std::string& resourceId,
        const ContainerUpdateContext& ctx,
        const std::vector<GroupGrantWithKey>& callerSupplied
    ) -> decltype(container.groups, container.contextId, std::optional<std::vector<server::GroupKeyEntrySet>>()) {
        auto grantees = resolveGranteesForRekey(container, callerSupplied);
        if (grantees.empty()) {
            return std::nullopt;
        }
        return buildGroupKeyEntries(grantees, ctx.key, ctx.dio, container.contextId, resourceId, ctx.secret);
    }

    void resolveGroupEpochs(
        const std::string& contextId,
        std::vector<GroupGrantWithKey>& grants,
        std::unordered_map<std::string, GroupEpochInfo>& groupCache
    );

    template<typename TModel>
    void fillContainerGroupGrants(
        TModel& model,
        const std::string& contextId,
        const std::string& resourceId,
        const EncKey& key,
        const DataIntegrityObject& dio,
        const std::string& secret,
        const std::vector<GroupGrantWithKey>& groups
    ) {
        // Populate groupEpoch and groupPubKey from current group state wherever the caller didn't supply them.
        std::vector<GroupGrantWithKey> resolved = groups;
        std::unordered_map<std::string, GroupEpochInfo> groupEpochCache;
        resolveGroupEpochs(contextId, resolved, groupEpochCache);
        std::vector<server::GroupGrant> grants;
        grants.reserve(resolved.size());
        for (const auto& g : resolved) {
            grants.push_back({.groupId = g.groupId, .role = g.role});
        }
        model.groups = std::move(grants);
        model.groupKeys = buildGroupKeyEntries(resolved, key, dio, contextId, resourceId, secret);
    }

    std::shared_ptr<privmx::utils::GuardedExecutor> _guardedExecutor;
    core::KeyProvider::GroupPrivKeyResolver _groupPrivKeyResolver;
    GroupEpochResolver _groupEpochResolver;

private:
    const core::KeyProvider::GroupPrivKeyResolver& groupPrivKeyResolverOr(
        const core::KeyProvider::GroupPrivKeyResolver& explicitResolver
    ) const {
        return explicitResolver ? explicitResolver : _groupPrivKeyResolver;
    }

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
) -> decltype(moduleObj.data, moduleObj.contextId, moduleObj.resourceId, core::DecryptedEncKeyV2()) {
    auto data_entry = moduleObj.data.back();
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    auto location{getModuleEncKeyLocation(moduleObj, moduleObj.resourceId)};
    if constexpr (module_has_keys<ModuleStruct>::value) {
        keyProviderRequest.addOne(moduleObj.keys, data_entry.keyId, location);
    }
    if constexpr (module_has_group_keys<ModuleStruct>::value) {
        keyProviderRequest.addGroupKeys(moduleObj.groupKeys, location);
    }
    core::DecryptedEncKeyV2 ret = _keyProvider
                                      ->getKeysAndVerify(
                                          keyProviderRequest, groupPrivKeyResolverOr(groupPrivKeyResolver)
                                      )
                                      .at(location)
                                      .at(data_entry.keyId);
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
) -> decltype(moduleObj.contextId, moduleObj.resourceId, std::unordered_map<std::string, DecryptedEncKeyV2>()) {
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    auto location{getModuleEncKeyLocation(moduleObj, resourceId)};
    if constexpr (module_has_keys<ModuleStruct>::value) {
        keyProviderRequest.addAll(moduleObj.keys, location);
    }
    if constexpr (module_has_group_keys<ModuleStruct>::value) {
        keyProviderRequest.addGroupKeys(moduleObj.groupKeys, location);
    }
    auto moduleKeys{
        _keyProvider->getKeysAndVerify(keyProviderRequest, groupPrivKeyResolverOr(groupPrivKeyResolver)).at(location)
    };
    return moduleKeys;
}

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_THREAD_THREADAPIIMPL_HPP_
