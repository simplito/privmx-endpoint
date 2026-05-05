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

server::StoreCreateResult_c_struct ServerApi::storeCreate(const server::StoreCreateModel_c_struct& model) {
    return request<server::StoreCreateResult_c_struct>("storeCreate", model.toJSON());
}

void ServerApi::storeUpdate(const server::StoreUpdateModel_c_struct& model) {
    requestVoid("storeUpdate", model.toJSON());
}

void ServerApi::storeDelete(const server::StoreDeleteModel_c_struct& model) {
    requestVoid("storeDelete", model.toJSON());
}

server::StoreGetResult_c_struct ServerApi::storeGet(const server::StoreGetModel_c_struct& model) {
    return request<server::StoreGetResult_c_struct>("storeGet", model.toJSON());
}

server::StoreListResult_c_struct ServerApi::storeList(const server::StoreListModel_c_struct& model) {
    return request<server::StoreListResult_c_struct>("storeList", model.toJSON());
}

server::StoreFileGetResult_c_struct ServerApi::storeFileGet(const server::StoreFileGetModel_c_struct& model) {
    return request<server::StoreFileGetResult_c_struct>("storeFileGet", model.toJSON());
}

server::StoreFileGetManyResult_c_struct ServerApi::storeFileGetMany(const server::StoreFileGetManyModel_c_struct& model) {
    return request<server::StoreFileGetManyResult_c_struct>("storeFileGetMany", model.toJSON());
}

server::StoreFileListResult_c_struct ServerApi::storeFileList(const server::StoreFileListModel_c_struct& model) {
    return request<server::StoreFileListResult_c_struct>("storeFileList", model.toJSON());
}

server::StoreFileCreateResult_c_struct ServerApi::storeFileCreate(const server::StoreFileCreateModel_c_struct& model) {
    return request<server::StoreFileCreateResult_c_struct>("storeFileCreate", model.toJSON());
}

server::StoreFileReadResult_c_struct ServerApi::storeFileRead(const server::StoreFileReadModel_c_struct& model) {
    return request<server::StoreFileReadResult_c_struct>("storeFileRead", model.toJSON());
}

void ServerApi::storeFileWrite(const server::StoreFileWriteModel_c_struct& model) {
    requestVoid("storeFileWrite", model.toJSON());
}

void ServerApi::storeFileWrite(const server::StoreFileWriteModelByOperations_c_struct& model) {
    requestVoid("storeFileWrite", model.toJSON());
}

void ServerApi::storeFileUpdate(const server::StoreFileUpdateModel_c_struct& model) {
    requestVoid("storeFileUpdate", model.toJSON());
}

void ServerApi::storeFileDelete(const server::StoreFileDeleteModel_c_struct& model) {
    requestVoid("storeFileDelete", model.toJSON());
}

template<class T> T ServerApi::request(const std::string& method, Poco::JSON::Object::Ptr params) {
    return T::fromJSON(_gateway->request("store." + method, params));
}

void ServerApi::requestVoid(const std::string& method, Poco::JSON::Object::Ptr params) {
    _gateway->request("store." + method, params);
}
