/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <algorithm>

#include "privmx/endpoint/group/GroupApiImpl.hpp"
#include "privmx/endpoint/group/GroupAwareModuleApi.hpp"
#include <privmx/endpoint/core/ConvertedExceptions.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::group;

GroupAwareModuleApi::GroupAwareModuleApi(
    const core::PrivateKey& userPrivKey,
    const std::shared_ptr<core::KeyProvider>& keyProvider,
    const std::string& host,
    const std::shared_ptr<core::EventMiddleware>& eventMiddleware,
    const core::Connection& connection,
    const std::optional<GroupApi>& groupApi
)
    : core::ContainerBaseApi(userPrivKey, keyProvider, host, eventMiddleware, connection),
      _groupApi(groupApi.has_value() ? groupApi->getImpl() : nullptr) {
    if (!_groupApi) {
        return;
    }
    initGroupPrivKeyResolver(
        [impl = _groupApi](const std::string& groupId, int64_t epoch) -> std::optional<core::PrivateKey> {
            try {
                return impl->resolveGroupPrivKey(groupId, epoch);
            } catch (...) {
                // not a member of this group at this epoch — skip
                return std::nullopt;
            }
        }
    );
}

GroupAwareModuleApi::~GroupAwareModuleApi() = default;

void GroupAwareModuleApi::absorbAutoRekeyFailure(const std::string& moduleId, const privmx::utils::PrivmxException& e) {
    auto code = core::ExceptionConverter::convert(e).getCode();
    if (code == privmx::endpoint::server::ContainerRotatedAlreadyException().getCode()) {
        invalidateModuleKeysInCache(moduleId);
        return;
    }
    if (code == privmx::endpoint::server::AccessDeniedException().getCode()) {
        throw core::StaleKeyRekeyRequiredException("automatic re-key of moduleId=" + moduleId + " was denied");
    }
    core::ExceptionConverter::rethrowAsCoreException(e);
    throw core::Exception("ExceptionConverter rethrow error");
}

void GroupAwareModuleApi::runRequiringCurrentKey(const std::string& moduleId, const std::function<void()>& operation) {
    try {
        operation();
    } catch (const privmx::utils::PrivmxException& e) {
        auto code = core::ExceptionConverter::convert(e).getCode();
        if (code == privmx::endpoint::server::ContainerGroupEpochOutdatedException().getCode()) {
            throw core::StaleKeyRekeyRequiredException("moduleId=" + moduleId + " has to be re-keyed by a manager");
        }
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void GroupAwareModuleApi::fillContainerCreateModel(
    core::server::ContainerCreateModelBase& model,
    const std::string& contextId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const core::ContainerCreateContext& ctx,
    Poco::Dynamic::Var encryptedData,
    const std::optional<std::vector<core::GroupGrantWithKey>>& groups
) {
    model.resourceId = ctx.resourceId;
    model.contextId = contextId;
    model.keyId = ctx.key.id;
    model.data = std::move(encryptedData);
    model.keys = ctx.keyEntries;
    model.users = core::EndpointUtils::usersWithPubKeyToIds(users);
    model.managers = core::EndpointUtils::usersWithPubKeyToIds(managers);
    if (groups.has_value() && !groups->empty()) {
        fillContainerGroupGrants(model, contextId, ctx.resourceId, ctx.key, ctx.dio, ctx.secret, groups.value());
    }
}

void GroupAwareModuleApi::fillContainerUpdateModel(
    core::server::ContainerUpdateModelBase& model,
    const std::string& id,
    const std::string& resourceId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const core::ContainerUpdateContext& ctx,
    int64_t version,
    bool force,
    const std::optional<std::vector<core::GroupGrantWithKey>>& groups
) {
    model.id = id;
    model.resourceId = resourceId;
    model.keyId = ctx.key.id;
    model.keys = ctx.keyEntries;
    model.users = core::EndpointUtils::usersWithPubKeyToIds(users);
    model.managers = core::EndpointUtils::usersWithPubKeyToIds(managers);
    model.version = version;
    model.force = force;
    if (groups.has_value()) {
        fillContainerGroupGrants(
            model, ctx.location.contextId, resourceId, ctx.key, ctx.dio, ctx.secret, groups.value()
        );
    }
}

ResolvedGroupGrants GroupAwareModuleApi::resolveGroupGrants(
    const std::string& contextId,
    const std::string& resourceId,
    const core::EncKey& key,
    const core::DataIntegrityObject& dio,
    const std::string& secret,
    const std::vector<core::GroupGrantWithKey>& groups
) {
    std::vector<core::GroupGrantWithKey> resolved = groups;
    std::unordered_map<std::string, core::GroupEpochInfo> groupEpochCache;
    resolveGroupEpochs(contextId, resolved, groupEpochCache);
    std::vector<core::server::GroupGrant> grants;
    grants.reserve(resolved.size());
    for (const auto& g : resolved) {
        grants.push_back({.groupId = g.groupId, .role = g.role});
    }
    return ResolvedGroupGrants{
        .grants = std::move(grants),
        .keyEntries = buildGroupKeyEntries(resolved, key, dio, contextId, resourceId, secret)
    };
}

bool GroupAwareModuleApi::doesGroupStateForceNewKey(
    const core::server::ContainerInfoBase& container,
    const std::vector<core::GroupGrantWithKey>& groups
) {
    for (const auto& current : container.groups) {
        auto kept = std::find_if(groups.begin(), groups.end(), [&](const core::GroupGrantWithKey& g) {
            return g.groupId == current.groupId;
        });
        if (kept == groups.end()) {
            return true;
        }
    }
    return !groups.empty() && isRekeyNeeded(container);
}

std::vector<core::GroupGrantWithKey> GroupAwareModuleApi::resolveGranteesForRekey(
    const core::server::ContainerInfoBase& container,
    const std::vector<core::GroupGrantWithKey>& knownGroupKeys
) {
    std::vector<core::GroupGrantWithKey> grants;
    grants.reserve(container.groups.size());
    for (const auto& grant : container.groups) {
        auto supplied = std::find_if(
            knownGroupKeys.begin(), knownGroupKeys.end(),
            [&](const core::GroupGrantWithKey& g) { return g.groupId == grant.groupId; }
        );
        if (supplied != knownGroupKeys.end()) {
            grants.push_back(
                core::GroupGrantWithKey{
                    .groupId = grant.groupId,
                    .role = grant.role,
                    .groupPubKey = supplied->groupPubKey,
                    .groupEpoch = supplied->groupEpoch
                }
            );
        } else {
            grants.push_back(
                core::GroupGrantWithKey{
                    .groupId = grant.groupId, .role = grant.role, .groupPubKey = {}, .groupEpoch = 0
                }
            );
        }
    }
    for (const auto& g : knownGroupKeys) {
        auto granted = std::find_if(
            container.groups.begin(), container.groups.end(),
            [&](const core::server::GroupGrant& grant) { return grant.groupId == g.groupId; }
        );
        if (granted == container.groups.end()) {
            LOG_WARN("[resolveGranteesForRekey] group ", g.groupId, " is not a grantee of this module — ignored")
        }
    }
    std::unordered_map<std::string, core::GroupEpochInfo> groupCache;
    resolveGroupEpochs(container.contextId, grants, groupCache);
    return grants;
}

std::optional<std::vector<core::server::GroupKeyEntrySet>> GroupAwareModuleApi::buildRekeyGroupKeyEntries(
    const core::server::ContainerInfoBase& container,
    const std::string& resourceId,
    const core::ContainerUpdateContext& ctx,
    const std::vector<core::GroupGrantWithKey>& knownGroupKeys
) {
    auto grantees = resolveGranteesForRekey(container, knownGroupKeys);
    if (grantees.empty()) {
        return std::nullopt;
    }
    return buildGroupKeyEntries(grantees, ctx.key, ctx.dio, container.contextId, resourceId, ctx.secret);
}

void GroupAwareModuleApi::resolveGroupEpochs(
    const std::string& contextId,
    std::vector<core::GroupGrantWithKey>& grants,
    std::unordered_map<std::string, core::GroupEpochInfo>& groupCache
) {
    auto isComplete = [](const core::GroupGrantWithKey& g) { return g.groupEpoch > 0 && !g.groupPubKey.empty(); };
    std::vector<std::string> toFetch;
    for (const auto& g : grants) {
        if (isComplete(g) || groupCache.find(g.groupId) != groupCache.end())
            continue;
        if (std::find(toFetch.begin(), toFetch.end(), g.groupId) == toFetch.end())
            toFetch.push_back(g.groupId);
    }
    if (!toFetch.empty() && _groupApi) {
        auto fetched = _groupApi->fetchGroupEpochs(contextId, toFetch);
        groupCache.insert(fetched.begin(), fetched.end());
    }
    for (auto& g : grants) {
        if (isComplete(g))
            continue;
        auto resolved = groupCache.find(g.groupId);
        if (resolved == groupCache.end()) {
            throw core::UnresolvedGroupGranteeException("groupId=" + g.groupId);
        }
        g.groupPubKey = resolved->second.groupPubKey;
        g.groupEpoch = resolved->second.keyVersion;
    }
}
