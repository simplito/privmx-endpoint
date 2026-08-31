#include "privmx/endpoint/group/ServerApi.hpp"
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

void ServerApi::groupUpdate(server::GroupUpdateModel model) {
    request("groupUpdate", model.toJSON());
}

void ServerApi::groupDelete(server::GroupDeleteModel model) {
    request("groupDelete", model.toJSON());
}

server::GroupGetResult ServerApi::groupGet(server::GroupGetModel model) {
    return request<server::GroupGetResult>("groupGet", model.toJSON());
}

server::GroupListResult ServerApi::groupList(server::GroupListModel model) {
    return request<server::GroupListResult>("groupList", model.toJSON());
}

void ServerApi::groupAddMember(server::GroupAddMemberModel model) {
    request("groupAddMember", model.toJSON());
}

void ServerApi::groupRemoveMember(server::GroupRemoveMemberModel model) {
    request("groupRemoveMember", model.toJSON());
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

template<class T>
T ServerApi::request(const std::string& method, Poco::JSON::Object::Ptr params) {
    return T::fromJSON(_gateway->request("context." + method, params));
}

Poco::Dynamic::Var ServerApi::request(const std::string& method, Poco::JSON::Object::Ptr params) {
    return _gateway->request("context." + method, params);
}
