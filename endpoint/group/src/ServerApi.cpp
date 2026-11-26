#include "privmx/endpoint/group/ServerApi.hpp"
#include "privmx/endpoint/group/GroupException.hpp"
#include <privmx/utils/JsonHelper.hpp>

using namespace privmx::endpoint::group;
using namespace privmx::endpoint;

ServerApi::ServerApi(privmx::privfs::RpcGateway::Ptr gateway) : _gateway(gateway) {}

server::GroupCreateResult ServerApi::groupCreate(server::GroupCreateModel model) {
    auto json = model.toJSON();
    if (json->has("type") && json->get("type").toString().empty()) {
        json->remove("type");
    }
    return request<server::GroupCreateResult>("groupCreate", json);
}

void ServerApi::groupUpdatePublicMeta(server::GroupUpdatePublicMetaModel model) {
    request("groupUpdatePublicMeta", model.toJSON());
}

void ServerApi::groupUpdatePrivateMeta(server::GroupUpdatePrivateMetaModel model) {
    request("groupUpdatePrivateMeta", model.toJSON());
}

void ServerApi::groupUpdatePolicy(server::GroupUpdatePolicyModel model) {
    request("groupUpdatePolicy", model.toJSON());
}

void ServerApi::groupDelete(server::GroupDeleteModel model) {
    request("groupDelete", model.toJSON());
}

server::GroupGetPublicKeyResult ServerApi::groupGetPublicKey(server::GroupGetPublicKeyModel model) {
    auto result = request<server::GroupGetPublicKeyResult>("groupGetPublicKey", model.toJSON());
    // Everything verified off the answer is bound to the id it carries, so it has to be the one asked for.
    if (result.group.id != model.groupId) {
        throw GroupDataIntegrityException();
    }
    return result;
}
void ServerApi::groupSetVisibility(server::GroupSetVisibilityModel model) {
    request("groupSetVisibility", model.toJSON());
}
void ServerApi::prefetchGroups(const std::vector<std::string>& groupIds) {
    static constexpr std::size_t BATCH = 128; // the bridge's limit for one call
    for (std::size_t from = 0; from < groupIds.size(); from += BATCH) {
        const std::size_t to = std::min(groupIds.size(), from + BATCH);
        Poco::JSON::Array::Ptr ids = new Poco::JSON::Array();
        for (std::size_t i = from; i < to; ++i) {
            ids->add(groupIds[i]);
        }
        Poco::JSON::Object::Ptr params = new Poco::JSON::Object();
        params->set("groupIds", ids);
        const auto answer = request("groupGetMany", params).extract<Poco::JSON::Object::Ptr>();
        const auto results = answer->getArray("results");
        if (results.isNull() || results->size() != to - from) {
            throw GroupDataIntegrityException();
        }
        for (std::size_t i = from; i < to; ++i) {
            const auto entry = results->getObject(static_cast<unsigned int>(i - from));
            if (entry.isNull() || !entry->has("group")) {
                continue;
            }
            server::GroupInfo group = server::GroupInfo::fromJSON(entry->get("group"));
            // Bound to the id asked for, as `groupGet` binds its own answer.
            if (group.id != groupIds[i]) {
                throw GroupDataIntegrityException();
            }
            std::lock_guard<std::mutex> lock(_prefetchedMutex);
            _prefetched.insert_or_assign(groupIds[i], std::move(group));
        }
    }
}

void ServerApi::dropPrefetched() {
    std::lock_guard<std::mutex> lock(_prefetchedMutex);
    _prefetched.clear();
}

server::GroupGetResult ServerApi::groupGet(server::GroupGetModel model) {
    if (!model.type.has_value() &&
        !model.scope.has_value() &&
        !model.forUserIds.has_value() &&
        !model.forNewMembers.has_value() &&
        !model.fromRosterVersion.has_value()) {
        std::lock_guard<std::mutex> lock(_prefetchedMutex);
        const auto kept = _prefetched.find(model.groupId);
        if (kept != _prefetched.end()) {
            server::GroupGetResult result{.group = std::move(kept->second)};
            _prefetched.erase(kept);
            return result;
        }
    }
    auto result = request<server::GroupGetResult>("groupGet", model.toJSON());
    // Everything verified off the answer is bound to the id it carries, so it has to be the one asked for.
    if (result.group.id != model.groupId) {
        throw GroupDataIntegrityException();
    }
    return result;
}

server::GroupListResult ServerApi::groupList(server::GroupListModel model) {
    return request<server::GroupListResult>("groupList", model.toJSON());
}

void ServerApi::groupAddMembers(server::GroupAddMembersModel model) {
    request("groupAddMembers", model.toJSON());
}

void ServerApi::groupRemoveMembers(server::GroupRemoveMembersModel model) {
    request("groupRemoveMembers", model.toJSON());
}

void ServerApi::groupReseat(server::GroupRemoveMembersModel model) {
    request("groupReseat", model.toJSON());
}

void ServerApi::groupSetRoles(server::GroupSetRolesModel model) {
    request("groupSetRoles", model.toJSON());
}

server::SpaceCreateResult ServerApi::spaceCreate(server::SpaceCreateModel model) {
    return request<server::SpaceCreateResult>("spaceCreate", model.toJSON());
}

server::SpaceGetResult ServerApi::spaceGet(server::SpaceIdModel model) {
    return request<server::SpaceGetResult>("spaceGet", model.toJSON());
}

server::SpaceListResult ServerApi::spaceList(server::SpaceListModel model) {
    return request<server::SpaceListResult>("spaceList", model.toJSON());
}

server::SpaceGetStatementsResult ServerApi::spaceGetStatements(server::SpaceGetStatementsModel model) {
    return request<server::SpaceGetStatementsResult>("spaceGetStatements", model.toJSON());
}

void ServerApi::spaceDelete(server::SpaceIdModel model) {
    request("spaceDelete", model.toJSON());
}

void ServerApi::spaceAddRecipients(server::SpaceAddRecipientsModel model) {
    request("spaceAddRecipients", model.toJSON());
}

server::SpaceRotateKeyResult ServerApi::spaceRotateKey(server::SpaceRotateKeyModel model) {
    const bool removal = model.groups.has_value() || model.users.has_value();
    return request<server::SpaceRotateKeyResult>(removal ? "spaceRemoveRecipients" : "spaceRotateKey", model.toJSON());
}

void ServerApi::spaceUpdatePublicMeta(server::SpaceUpdateMetaModel model) {
    request("spaceUpdatePublicMeta", model.toJSON());
}

void ServerApi::spaceUpdatePrivateMeta(server::SpaceUpdateMetaModel model) {
    request("spaceUpdatePrivateMeta", model.toJSON());
}

void ServerApi::groupSelfUpdate(server::GroupSelfUpdateModel model) {
    request("groupSelfUpdate", model.toJSON());
}

void ServerApi::groupGenerateNewKey(server::GroupGenerateNewKeyModel model) {
    request("groupGenerateNewKey", model.toJSON());
}

server::GroupGetTreeCommitsResult ServerApi::groupGetTreeCommits(server::GroupGetTreeCommitsModel model) {
    return request<server::GroupGetTreeCommitsResult>("groupGetTreeCommits", model.toJSON());
}

void ServerApi::groupCutEra(server::GroupCutEraModel model) {
    request("groupCutEra", model.toJSON());
}

void ServerApi::groupPruneArchive(server::GroupPruneArchiveModel model) {
    request("groupPruneArchive", model.toJSON());
}

server::GroupGetKeyArchiveResult ServerApi::groupGetKeyArchive(server::GroupGetKeyArchiveModel model) {
    return request<server::GroupGetKeyArchiveResult>("groupGetKeyArchive", model.toJSON());
}

server::GroupGetEpochKeysResult ServerApi::groupGetEpochKeys(server::GroupGetEpochKeysModel model) {
    return request<server::GroupGetEpochKeysResult>("groupGetEpochKeys", model.toJSON());
}

void ServerApi::groupRepairRung(server::GroupRepairRungModel model) {
    request("groupRepairRung", model.toJSON());
}

void ServerApi::groupSendCustomEvent(server::GroupSendCustomEventModel model) {
    request("groupSendCustomEvent", model.toJSON());
}

template<class T>
T ServerApi::request(const std::string& method, Poco::JSON::Object::Ptr params) {
    return T::fromJSON(_gateway->request("context." + method, params));
}

Poco::Dynamic::Var ServerApi::request(const std::string& method, Poco::JSON::Object::Ptr params) {
    return _gateway->request("context." + method, params);
}
