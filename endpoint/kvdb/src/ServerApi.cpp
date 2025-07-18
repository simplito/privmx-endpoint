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

server::KvdbEntryGetResult ServerApi::kvdbEntryGet(server::KvdbEntryGetModel model) {
    return request<server::KvdbEntryGetResult>("kvdbEntryGet", model);
}

void ServerApi::kvdbEntrySet(server::KvdbEntrySetModel model) {
    request("kvdbEntrySet", model);
}

void ServerApi::kvdbEntryDelete(server::KvdbEntryDeleteModel model) {
    request("kvdbEntryDelete", model);
}

server::KvdbListKeysResult ServerApi::kvdbListKeys(server::KvdbListKeysModel model) {
    return request<server::KvdbListKeysResult>("kvdbListKeys", model);
}

server::KvdbListEntriesResult ServerApi::kvdbListEntries(server::KvdbListEntriesModel model) {
    return request<server::KvdbListEntriesResult>("kvdbListEntries", model);
}

server::KvdbEntryDeleteManyResult ServerApi::kvdbEntryDeleteMany(server::KvdbEntryDeleteManyModel model) {
    return request<server::KvdbEntryDeleteManyResult>("kvdbEntryDeleteMany", model);
}

template<class T> T ServerApi::request(const std::string& method, Poco::JSON::Object::Ptr params) {  //only typed object
    return privmx::utils::TypedObjectFactory::createObjectFromVar<T>(_gateway->request("kvdb." + method, params));
}

Poco::Dynamic::Var ServerApi::request(const std::string& method, Poco::JSON::Object::Ptr params) {  //var
    return _gateway->request("kvdb." + method, params);
}