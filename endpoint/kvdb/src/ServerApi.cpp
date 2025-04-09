/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/kvdb/ServerApi.hpp"

using namespace privmx::endpoint::kvdb;
using namespace privmx::endpoint;

ServerApi::ServerApi(privmx::privfs::RpcGateway::Ptr gateway) : _gateway(gateway) {}

server::KvdbCreateResult ServerApi::kvdbCreate(server::KvdbCreateModel model) {
    return request<server::KvdbCreateResult>("kvdbCreate", model);
}

void ServerApi::kvdbUpdate(server::KvdbUpdateModel model) {
    request("kvdbUpdate", model);
}

void ServerApi::kvdbDelete(server::KvdbDeleteModel model) {
    request("kvdbDelete", model);
}

server::KvdbDeleteManyResult ServerApi::kvdbDeleteMany(server::KvdbDeleteManyModel model) {
    return request<server::KvdbDeleteManyResult>("kvdbDeleteMany", model);
}

server::KvdbGetResult ServerApi::kvdbGet(server::KvdbGetModel model) {
    return request<server::KvdbGetResult>("kvdbGet", model);
}

server::KvdbListResult ServerApi::kvdbList(server::KvdbListModel model) {
    return request<server::KvdbListResult>("kvdbList", model);
}

server::KvdbItemGetResult ServerApi::kvdbItemGet(server::KvdbItemGetModel model) {
    return request<server::KvdbItemGetResult>("kvdbItemGet", model);
}

void ServerApi::kvdbItemSet(server::KvdbItemSetModel model) {
    request("kvdbItemSet", model);
}

void ServerApi::kvdbItemDelete(server::KvdbItemDeleteModel model) {
    request("kvdbItemDelete", model);
}

server::KvdbListKeysResult ServerApi::kvdbListKeys(server::KvdbListKeysModel model) {
    return request<server::KvdbListKeysResult>("kvdbListKeys", model);
}

server::KvdbListItemsResult ServerApi::kvdbListItems(server::KvdbListItemsModel model) {
    return request<server::KvdbListItemsResult>("kvdbListItems", model);
}

server::KvdbItemDeleteManyResult ServerApi::kvdbItemDeleteMany(server::KvdbItemDeleteManyModel model) {
    return request<server::KvdbItemDeleteManyResult>("kvdbItemDeleteMany", model);
}

template<class T> T ServerApi::request(const std::string& method, Poco::JSON::Object::Ptr params) {  //only typed object
    return privmx::utils::TypedObjectFactory::createObjectFromVar<T>(_gateway->request("kvdb." + method, params));
}

Poco::Dynamic::Var ServerApi::request(const std::string& method, Poco::JSON::Object::Ptr params) {  //var
    return _gateway->request("kvdb." + method, params);
}