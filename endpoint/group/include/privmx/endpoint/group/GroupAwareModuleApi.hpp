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
#include <privmx/endpoint/group/GroupTypes.hpp>

namespace privmx {
namespace endpoint {
namespace group {

// The base for every container module that can be granted to a group.
class GroupAwareModuleApi : public core::ContainerBaseApi {
public:
    GroupAwareModuleApi(
        const core::PrivateKey& userPrivKey,
        const std::shared_ptr<core::KeyProvider>& keyProvider,
        const std::string& host,
        const std::shared_ptr<core::EventMiddleware>& eventMiddleware,
        const core::Connection& connection,
        const std::optional<GroupApi>& groupApi
    );

    ~GroupAwareModuleApi() override;

protected:
    // The two outcomes of a self-started re-key that are not failures: a lost race, and a refusal, which becomes
    // `StaleKeyRekeyRequiredException`. An unresolved grantee group stays a failure — it cannot re-key at all.
    void absorbAutoRekeyFailure(const std::string& moduleId, const privmx::utils::PrivmxException& e);

    // For a write that cannot re-key its way out: an Inbox submission seals to the entries public key and its
    // sender may not be named on the container at all, so only a manager can clear a stale epoch.
    void runRequiringCurrentKey(const std::string& moduleId, const std::function<void()>& operation);

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

    // The container's own grantee list, each entry carrying the epoch public key to seal the new key to.
    // `knownGroupKeys` only pre-fills those the caller already verified; the rest are read from the Bridge.
    std::vector<core::GroupGrantWithKey> resolveGranteesForRekey(
        const core::server::ContainerInfoBase& container,
        const std::vector<core::GroupGrantWithKey>& knownGroupKeys
    );

    std::optional<std::vector<core::server::GroupKeyEntrySet>> buildRekeyGroupKeyEntries(
        const core::server::ContainerInfoBase& container,
        const std::string& resourceId,
        const core::ContainerUpdateContext& ctx,
        const std::vector<core::GroupGrantWithKey>& knownGroupKeys
    );

    // `knownGroupKeys` grants and revokes nothing — the grantee list is the container's own, and these only save
    // a round trip. Contrast `fillContainerUpdateModel`, whose `groups` *is* the new grantee list.
    template<typename TRotateModel, typename TContainer>
    void rotateContainerKeys(
        const std::string& id,
        const TContainer& container,
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers,
        int64_t version,
        bool force,
        const std::vector<core::GroupGrantWithKey>& knownGroupKeys,
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

        model.groupKeys = buildRekeyGroupKeyEntries(container, resourceId, ctx, knownGroupKeys);

        sendRotateRequest(model);
        invalidateModuleKeysInCache(id);
    }

    // `fetchContainer` must re-read rather than reuse a snapshot: the roster and version this re-key is built on
    // have to be the ones the bridge will check it against.
    template<typename TRotateModel, typename TContainer>
    void autoRotateContainerKeys(
        const std::string& moduleId,
        const std::function<TContainer()>& fetchContainer,
        const std::function<void(const TRotateModel&)>& sendRotateRequest
    ) {
        auto container = fetchContainer();
        if (!isRekeyNeeded(container)) {
            return;
        }
        auto roster = resolveRosterPubKeys(container.contextId, container.users, container.managers);
        try {
            rotateContainerKeys<TRotateModel>(
                moduleId, container, roster.users, roster.managers, container.version, false, {}, sendRotateRequest
            );
        } catch (const privmx::utils::PrivmxException& e) { absorbAutoRekeyFailure(moduleId, e); }
    }

private:
    ResolvedGroupGrants resolveGroupGrants(
        const std::string& contextId,
        const std::string& resourceId,
        const core::EncKey& key,
        const core::DataIntegrityObject& dio,
        const std::string& secret,
        const std::vector<core::GroupGrantWithKey>& groups
    );

    std::shared_ptr<GroupApiImpl> _groupApi;
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_GROUPAWAREMODULEAPI_HPP_
