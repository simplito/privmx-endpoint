/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/kvdb/ServerApi.hpp"
#include <privmx/utils/JsonHelper.hpp>

using namespace privmx::endpoint::kvdb;
using namespace privmx::endpoint;

ServerApi::ServerApi(privmx::privfs::RpcGateway::Ptr gateway) : _gateway(gateway) {}

server::KvdbCreateResult_c_struct ServerApi::kvdbCreate(server::KvdbCreateModel_c_struct model) {
    return request<server::KvdbCreateResult_c_struct>("kvdbCreate", model.toJSON());
}

void ServerApi::kvdbUpdate(server::KvdbUpdateModel_c_struct model) {
    request("kvdbUpdate", model.toJSON());
}

void ServerApi::kvdbDelete(server::KvdbDeleteModel_c_struct model) {
    request("kvdbDelete", model.toJSON());
}

server::KvdbDeleteManyResult_c_struct ServerApi::kvdbDeleteMany(server::KvdbDeleteManyModel_c_struct model) {
    return request<server::KvdbDeleteManyResult_c_struct>("kvdbDeleteMany", model.toJSON());
}

server::KvdbGetResult_c_struct ServerApi::kvdbGet(server::KvdbGetModel_c_struct model) {
    return request<server::KvdbGetResult_c_struct>("kvdbGet", model.toJSON());
}

server::KvdbListResult_c_struct ServerApi::kvdbList(server::KvdbListModel_c_struct model) {
    return request<server::KvdbListResult_c_struct>("kvdbList", model.toJSON());
}

server::KvdbEntryGetResult_c_struct ServerApi::kvdbEntryGet(server::KvdbEntryGetModel_c_struct model) {
    return request<server::KvdbEntryGetResult_c_struct>("kvdbEntryGet", model.toJSON());
}

void ServerApi::kvdbEntrySet(server::KvdbEntrySetModel_c_struct model) {
    request("kvdbEntrySet", model.toJSON());
}

void ServerApi::kvdbEntryDelete(server::KvdbEntryDeleteModel_c_struct model) {
    request("kvdbEntryDelete", model.toJSON());
}

server::KvdbListKeysResult_c_struct ServerApi::kvdbListKeys(server::KvdbListKeysModel_c_struct model) {
    return request<server::KvdbListKeysResult_c_struct>("kvdbListKeys", model.toJSON());
}

server::KvdbListEntriesResult_c_struct ServerApi::kvdbListEntries(server::KvdbListEntriesModel_c_struct model) {
    return request<server::KvdbListEntriesResult_c_struct>("kvdbListEntries", model.toJSON());
}

server::KvdbEntryDeleteManyResult_c_struct ServerApi::kvdbEntryDeleteMany(server::KvdbEntryDeleteManyModel_c_struct model) {
    return request<server::KvdbEntryDeleteManyResult_c_struct>("kvdbEntryDeleteMany", model.toJSON());
}

template<class T> T ServerApi::request(const std::string& method, Poco::JSON::Object::Ptr params) {
    return T::fromJSON(_gateway->request("kvdb." + method, params));
}

Poco::Dynamic::Var ServerApi::request(const std::string& method, Poco::JSON::Object::Ptr params) {
    return _gateway->request("kvdb." + method, params);
}
