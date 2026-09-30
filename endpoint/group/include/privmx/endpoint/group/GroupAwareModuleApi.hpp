/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_GROUP_GROUPAWAREMODULEAPI_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_GROUPAWAREMODULEAPI_HPP_

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <vector>

#include <privmx/endpoint/core/ContainerBaseApi.hpp>
#include <privmx/endpoint/group/GroupApi.hpp>

namespace privmx {
namespace endpoint {
namespace group {

// The base for every container module that can be granted to a group. It sits in the group module rather than in
// core because it reads a group's published epoch and grant key, which only `GroupApiImpl` can serve.
//
// Every served container here inherits `core::server::ContainerInfoBase`, so most of this takes it by reference
// rather than by template — only `data`, whose entry type differs per module, still needs one.
class GroupAwareModuleApi : public core::ContainerBaseApi {
public:
    GroupAwareModuleApi(
        const privmx::crypto::PrivateKey& userPrivKey,
        const std::shared_ptr<core::KeyProvider>& keyProvider,
        const std::string& host,
        const std::shared_ptr<core::EventMiddleware>& eventMiddleware,
        const core::Connection& connection,
        const std::optional<GroupApi>& groupApi
    );

    ~GroupAwareModuleApi() override;

protected:
    // Runs a re-key the library started on its own, absorbing the two outcomes that are not failures: a lost race
    // (somebody else did the work) and a refusal, which becomes the `StaleKeyRekeyRequiredException` the caller
    // would have been given before any of this existed. `UnresolvedGroupGranteeException` is deliberately a real
    // failure: a caller in none of the grantee groups cannot read their epoch keys and so cannot re-key at all.
    void runAutoRekey(const std::string& moduleId, const std::function<void()>& rotate);

    // A write with no re-key to fall back on, so the bridge's epoch refusal reaches the caller as the same
    // `StaleKeyRekeyRequiredException` a stale container key raises everywhere else. An Inbox submission is the
    // case: it seals to the entries public key and its sender may not be named on the container at all.
    void runWithoutAutoRekey(const std::string& moduleId, const std::function<void()>& write);

    // Puts a public key and current epoch to each grantee group named on a create or an update.
    void resolveGroupEpochs(
        const std::string& contextId,
        std::vector<core::GroupGrantWithKey>& grants,
        std::unordered_map<std::string, core::GroupEpochInfo>& groupCache
    );

    void fillContainerCreateModel(
        core::server::ContainerCreateModelBase& model,
        const std::string& contextId,
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers,
        const core::ContainerCreateContext& ctx,
        Poco::Dynamic::Var encryptedData,
        const std::optional<std::vector<core::GroupGrantWithKey>>& groups = std::nullopt
    );

    void fillContainerUpdateModel(
        core::server::ContainerUpdateModelBase& model,
        const std::string& id,
        const std::string& resourceId,
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers,
        const core::ContainerUpdateContext& ctx,
        int64_t version,
        bool force,
        const std::optional<std::vector<core::GroupGrantWithKey>>& groups = std::nullopt
    );

    // Templated because the Inbox models stand on their own rather than on the container model bases, while
    // carrying the same two grant fields. The work itself is in `resolveGroupGrants`.
    template<typename TModel>
    void fillContainerGroupGrants(
        TModel& model,
        const std::string& contextId,
        const std::string& resourceId,
        const core::EncKey& key,
        const core::DataIntegrityObject& dio,
        const std::string& secret,
        const std::vector<core::GroupGrantWithKey>& groups
    ) {
        auto resolved = resolveGroupGrants(contextId, resourceId, key, dio, secret, groups);
        model.groups = std::move(resolved.grants);
        model.groupKeys = std::move(resolved.keyEntries);
    }

    // Runs an item write against the module's current keys, retrying once if the key turns out to be spent.
    // `autoRekey`, when given, makes a stale key recoverable: the container is re-keyed and the write retried.
    template<typename TReturn>
    TReturn withKeyRefresh(
        const std::string& moduleId,
        int64_t invalidKeyCode,
        std::function<TReturn(const core::ModuleKeys&)> op,
        const std::function<void()>& autoRekey = nullptr
    ) {
        auto keys = getModuleKeys(moduleId);
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
            if (autoRekey && code == privmx::endpoint::server::ContainerGroupEpochOutdatedException().getCode()) {
                autoRekey();
                return op(getNewModuleKeysAndUpdateCache(moduleId));
            }
            throw;
        }
    }

    static bool doesGroupStateForceNewKey(
        const core::server::ContainerInfoBase& container,
        const std::vector<core::GroupGrantWithKey>& groups
    );

    std::vector<core::GroupGrantWithKey> resolveGranteesForRekey(
        const core::server::ContainerInfoBase& container,
        const std::vector<core::GroupGrantWithKey>& callerSupplied
    );

    std::optional<std::vector<core::server::GroupKeyEntrySet>> buildRekeyGroupKeyEntries(
        const core::server::ContainerInfoBase& container,
        const std::string& resourceId,
        const core::ContainerUpdateContext& ctx,
        const std::vector<core::GroupGrantWithKey>& callerSupplied
    );

    // Re-encrypts a container's key for its current members and grantee groups, changing nothing else. The caller
    // fetches the container and supplies `sendRotateRequest`; everything between is the same for every type.
    template<typename TRotateModel, typename TContainer>
    void rotateContainerKeys(
        const std::string& id,
        const TContainer& container,
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers,
        int64_t version,
        bool force,
        const std::vector<core::GroupGrantWithKey>& groups,
        const std::function<void(const TRotateModel&)>& sendRotateRequest
    ) {
        static_assert(
            std::is_base_of_v<core::server::ContainerRotateKeysModelBase, TRotateModel>,
            "TRotateModel must inherit from ContainerRotateKeysModelBase"
        );
        static_assert(
            std::is_base_of_v<core::server::ContainerInfoBase, TContainer>,
            "TContainer must inherit from ContainerInfoBase"
        );
        const auto& currentEntry = container.data.back();
        auto resourceId = container.resourceId.value_or(core::EndpointUtils::generateId());
        auto ctx = prepareContainerUpdate(container, currentEntry, resourceId, users, managers, true);

        TRotateModel model;
        model.id = id;
        model.keyId = ctx.key.id;
        model.keys = ctx.keyEntries;
        model.version = version;
        model.force = force;

        model.groupKeys = buildRekeyGroupKeyEntries(container, resourceId, ctx, groups);

        sendRotateRequest(model);
        invalidateModuleKeysInCache(id);
    }

    // A re-key the library starts on its own, after a write met a stale container key. `fetchContainer` re-reads
    // the container: whatever triggered this may have been a stale snapshot, and the roster and version this
    // re-key is built on have to be the ones the bridge will check it against.
    template<typename TRotateModel, typename TContainer>
    void autoRotateContainerKeys(
        const std::string& moduleId,
        const std::function<TContainer()>& fetchContainer,
        const std::function<void(const TRotateModel&)>& sendRotateRequest
    ) {
        auto container = fetchContainer();
        if (!isRekeyNeeded(container)) {
            // Someone else already re-keyed it. The caller refetches the keys either way, so there is nothing to do.
            return;
        }
        auto roster = resolveRosterPubKeys(container.contextId, container.users, container.managers);
        runAutoRekey(moduleId, [&] {
            rotateContainerKeys<TRotateModel>(
                moduleId, container, roster.users, roster.managers, container.version, false, {}, sendRotateRequest
            );
        });
    }

private:
    // Grantee groups resolved to the epoch and public key each holds right now, with the module key sealed to it.
    struct ResolvedGroupGrants {
        std::vector<core::server::GroupGrant> grants;
        std::vector<core::server::GroupKeyEntrySet> keyEntries;
    };

    ResolvedGroupGrants resolveGroupGrants(
        const std::string& contextId,
        const std::string& resourceId,
        const core::EncKey& key,
        const core::DataIntegrityObject& dio,
        const std::string& secret,
        const std::vector<core::GroupGrantWithKey>& groups
    );

    // Null when the module was created without a GroupApi, which leaves it group-unaware: a container granted to
    // a group then cannot be read or written, and `resolveGroupEpochs` refuses rather than guessing.
    std::shared_ptr<GroupApiImpl> _groupApi;
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_GROUPAWAREMODULEAPI_HPP_
