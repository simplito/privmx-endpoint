/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/group/ServerApi.hpp"

using namespace privmx::endpoint::group;
using namespace privmx::endpoint;

ServerApi::ServerApi(privmx::privfs::RpcGateway::Ptr gateway) : _gateway(gateway) {}

server::GroupCreateResult ServerApi::groupCreate(server::GroupCreateModel model) {
    return request<server::GroupCreateResult>("groupCreate", model);
}

void ServerApi::groupUpdate(server::GroupUpdateModel model) {
    request("groupUpdate", model);
}

void ServerApi::groupDelete(server::GroupDeleteModel model) {
    request("groupDelete", model);
}

server::GroupGetResult ServerApi::groupGet(server::GroupGetModel model) {
    return request<server::GroupGetResult>("groupGet", model);
}

server::GroupListResult ServerApi::groupList(server::GroupListModel model) {
    return request<server::GroupListResult>("groupList", model);
}

template<class T> T ServerApi::request(const std::string& method, Poco::JSON::Object::Ptr params) {  //only typed object
    return privmx::utils::TypedObjectFactory::createObjectFromVar<T>(_gateway->request("group." + method, params));
}

Poco::Dynamic::Var ServerApi::request(const std::string& method, Poco::JSON::Object::Ptr params) {  //var
    return _gateway->request("group." + method, params);
}