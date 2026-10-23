/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/kvdb/ServerApi.hpp"
#include <privmx/endpoint/core/EndpointUtils.hpp>
#include <privmx/utils/JsonHelper.hpp>

using namespace privmx::endpoint::kvdb;
using namespace privmx::endpoint;

ServerApi::ServerApi(privmx::privfs::RpcGateway::Ptr gateway) : _gateway(gateway) {}

server::KvdbCreateResult ServerApi::kvdbCreate(server::KvdbCreateModel model) {
    return request<server::KvdbCreateResult>("kvdbCreate", model.toJSON());
}

void ServerApi::kvdbUpdate(server::KvdbUpdateModel model) {
    request("kvdbUpdate", model.toJSON());
}

void ServerApi::kvdbRotateKeys(server::KvdbRotateKeysModel model) {
    request("kvdbRotateKeys", model.toJSON());
}

void ServerApi::kvdbDelete(server::KvdbDeleteModel model) {
    request("kvdbDelete", model.toJSON());
}

server::KvdbDeleteManyResult ServerApi::kvdbDeleteMany(server::KvdbDeleteManyModel model) {
    return request<server::KvdbDeleteManyResult>("kvdbDeleteMany", model.toJSON());
}

server::KvdbGetResult ServerApi::kvdbGet(server::KvdbGetModel model) {
    auto result = request<server::KvdbGetResult>("kvdbGet", model.toJSON());
    core::EndpointUtils::assertServedId(model.kvdbId, result.kvdb.id);
    return result;
}

server::KvdbListResult ServerApi::kvdbList(server::KvdbListModel model) {
    return request<server::KvdbListResult>("kvdbList", model.toJSON());
}

server::KvdbEntryGetResult ServerApi::kvdbEntryGet(server::KvdbEntryGetModel model) {
    auto result = request<server::KvdbEntryGetResult>("kvdbEntryGet", model.toJSON());
    core::EndpointUtils::assertServedId(model.kvdbId, result.kvdbEntry.kvdbId);
    return result;
}

server::KvdbEntryFindResult ServerApi::kvdbEntryFind(server::KvdbEntryGetModel model) {
    auto result = request<server::KvdbEntryFindResult>("kvdbEntryFind", model.toJSON());
    if (result.kvdbEntry.has_value()) {
        core::EndpointUtils::assertServedId(model.kvdbId, result.kvdbEntry->kvdbId);
    }
    return result;
}

void ServerApi::kvdbEntrySet(server::KvdbEntrySetModel model) {
    request("kvdbEntrySet", model.toJSON());
}

void ServerApi::kvdbEntryDelete(server::KvdbEntryDeleteModel model) {
    request("kvdbEntryDelete", model.toJSON());
}

server::KvdbListKeysResult ServerApi::kvdbListKeys(server::KvdbListKeysModel model) {
    auto result = request<server::KvdbListKeysResult>("kvdbListKeys", model.toJSON());
    core::EndpointUtils::assertServedId(model.kvdbId, result.kvdb.id);
    return result;
}

server::KvdbListEntriesResult ServerApi::kvdbListEntries(server::KvdbListEntriesModel model) {
    auto result = request<server::KvdbListEntriesResult>("kvdbListEntries", model.toJSON());
    core::EndpointUtils::assertServedId(model.kvdbId, result.kvdb.id);
    return result;
}

server::KvdbEntryDeleteManyResult ServerApi::kvdbEntryDeleteMany(server::KvdbEntryDeleteManyModel model) {
    return request<server::KvdbEntryDeleteManyResult>("kvdbEntryDeleteMany", model.toJSON());
}

template<class T>
T ServerApi::request(const std::string& method, Poco::JSON::Object::Ptr params) {
    return T::fromJSON(_gateway->request("kvdb." + method, params));
}

Poco::Dynamic::Var ServerApi::request(const std::string& method, Poco::JSON::Object::Ptr params) {
    return _gateway->request("kvdb." + method, params);
}
