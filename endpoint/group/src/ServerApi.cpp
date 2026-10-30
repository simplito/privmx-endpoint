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

server::GroupGetResult ServerApi::groupGet(server::GroupGetModel model) {
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
