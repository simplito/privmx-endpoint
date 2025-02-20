/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/endpoint/store/ServerApi.hpp>

using namespace privmx::endpoint::store;

ServerApi::ServerApi(const privfs::RpcGateway::Ptr& gateway) : _gateway(gateway) {}

server::StoreCreateResult ServerApi::storeCreate(const server::StoreCreateModel& model) {
    return request<server::StoreCreateResult>("storeCreate", model);
}

void ServerApi::storeUpdate(const server::StoreUpdateModel& model) {
    request("storeUpdate", model);
}

void ServerApi::storeDelete(const server::StoreDeleteModel& model) {
    request("storeDelete", model);
}

server::StoreGetResult ServerApi::storeGet(const server::StoreGetModel& model) {
    return request<server::StoreGetResult>("storeGet", model);
}

server::StoreListResult ServerApi::storeList(const server::StoreListModel& model) {
    return request<server::StoreListResult>("storeList", model);
}

server::StoreFileGetResult ServerApi::storeFileGet(const server::StoreFileGetModel& model) {
    return request<server::StoreFileGetResult>("storeFileGet", model);
}

server::StoreFileGetManyResult ServerApi::storeFileGetMany(const server::StoreFileGetManyModel& model) {
    return request<server::StoreFileGetManyResult>("storeFileGetMany", model);
}

server::StoreFileListResult ServerApi::storeFileList(const server::StoreFileListModel& model) {
    return request<server::StoreFileListResult>("storeFileList", model);
}

server::StoreFileCreateResult ServerApi::storeFileCreate(const server::StoreFileCreateModel& model) {
    return request<server::StoreFileCreateResult>("storeFileCreate", model);
}

server::StoreFileReadResult ServerApi::storeFileRead(const server::StoreFileReadModel& model) {
    return request<server::StoreFileReadResult>("storeFileRead", model);
}

void ServerApi::storeFileWrite(const server::StoreFileWriteModel& model) {
    request("storeFileWrite", model);
}

void ServerApi::storeFileUpdate(const server::StoreFileUpdateModel& model) {
    request("storeFileUpdate", model);
}

void ServerApi::storeFileDelete(const server::StoreFileDeleteModel& model) {
    request("storeFileDelete", model);
}

void ServerApi::storeSendCustomEvent(server::StoreEmitCustomEventModel model) {
    request("storeSendCustomEvent", model);
}

template<class T> T ServerApi::request(const std::string& method, const Poco::JSON::Object::Ptr& params) {  //only typed object
    return privmx::utils::TypedObjectFactory::createObjectFromVar<T>(_gateway->request("store." + method, params));
}

Poco::Dynamic::Var ServerApi::request(const std::string& method, const Poco::JSON::Object::Ptr& params) {  //var
    return _gateway->request("store." + method, params);
}