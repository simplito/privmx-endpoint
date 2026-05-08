/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/utils/JsonHelper.hpp>
#include <privmx/endpoint/store/ServerApi.hpp>

using namespace privmx::endpoint::store;

ServerApi::ServerApi(const privfs::RpcGateway::Ptr& gateway) : _gateway(gateway) {}

server::StoreCreateResult ServerApi::storeCreate(const server::StoreCreateModel& model) {
    return request<server::StoreCreateResult>("storeCreate", model.toJSON());
}

void ServerApi::storeUpdate(const server::StoreUpdateModel& model) {
    requestVoid("storeUpdate", model.toJSON());
}

void ServerApi::storeDelete(const server::StoreDeleteModel& model) {
    requestVoid("storeDelete", model.toJSON());
}

server::StoreGetResult ServerApi::storeGet(const server::StoreGetModel& model) {
    return request<server::StoreGetResult>("storeGet", model.toJSON());
}

server::StoreListResult ServerApi::storeList(const server::StoreListModel& model) {
    return request<server::StoreListResult>("storeList", model.toJSON());
}

server::StoreFileGetResult ServerApi::storeFileGet(const server::StoreFileGetModel& model) {
    return request<server::StoreFileGetResult>("storeFileGet", model.toJSON());
}

server::StoreFileGetManyResult ServerApi::storeFileGetMany(const server::StoreFileGetManyModel& model) {
    return request<server::StoreFileGetManyResult>("storeFileGetMany", model.toJSON());
}

server::StoreFileListResult ServerApi::storeFileList(const server::StoreFileListModel& model) {
    return request<server::StoreFileListResult>("storeFileList", model.toJSON());
}

server::StoreFileCreateResult ServerApi::storeFileCreate(const server::StoreFileCreateModel& model) {
    return request<server::StoreFileCreateResult>("storeFileCreate", model.toJSON());
}

server::StoreFileReadResult ServerApi::storeFileRead(const server::StoreFileReadModel& model) {
    return request<server::StoreFileReadResult>("storeFileRead", model.toJSON());
}

void ServerApi::storeFileWrite(const server::StoreFileWriteModel& model) {
    requestVoid("storeFileWrite", model.toJSON());
}

void ServerApi::storeFileWrite(const server::StoreFileWriteModelByOperations& model) {
    requestVoid("storeFileWrite", model.toJSON());
}

void ServerApi::storeFileUpdate(const server::StoreFileUpdateModel& model) {
    requestVoid("storeFileUpdate", model.toJSON());
}

void ServerApi::storeFileDelete(const server::StoreFileDeleteModel& model) {
    requestVoid("storeFileDelete", model.toJSON());
}

template<class T> T ServerApi::request(const std::string& method, Poco::JSON::Object::Ptr params) {
    return T::fromJSON(_gateway->request("store." + method, params));
}

void ServerApi::requestVoid(const std::string& method, Poco::JSON::Object::Ptr params) {
    _gateway->request("store." + method, params);
}
