/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/thread/ServerApi.hpp"
#include <privmx/utils/JsonHelper.hpp>

using namespace privmx::endpoint::thread;
using namespace privmx::endpoint;

ServerApi::ServerApi(privmx::privfs::RpcGateway::Ptr gateway) : _gateway(gateway) {}

server::ThreadCreateResult_c_struct ServerApi::threadCreate(server::ThreadCreateModel_c_struct model) {
    return request<server::ThreadCreateResult_c_struct>("threadCreate", model.toJSON());
}

void ServerApi::threadUpdate(server::ThreadUpdateModel_c_struct model) {
    request("threadUpdate", model.toJSON());
}

void ServerApi::threadDelete(server::ThreadDeleteModel_c_struct model) {
    request("threadDelete", model.toJSON());
}

server::ThreadGetResult_c_struct ServerApi::threadGet(server::ThreadGetModel_c_struct model) {
    return request<server::ThreadGetResult_c_struct>("threadGet", model.toJSON());
}

server::ThreadListResult_c_struct ServerApi::threadList(server::ThreadListModel_c_struct model) {
    return request<server::ThreadListResult_c_struct>("threadList", model.toJSON());
}

server::ThreadMessageSendResult_c_struct ServerApi::threadMessageSend(server::ThreadMessageSendModel_c_struct model) {
    return request<server::ThreadMessageSendResult_c_struct>("threadMessageSend", model.toJSON());
}

void ServerApi::threadMessageDelete(server::ThreadMessageDeleteModel_c_struct model) {
    request("threadMessageDelete", model.toJSON());
}

server::ThreadMessageGetResult_c_struct ServerApi::threadMessageGet(server::ThreadMessageGetModel_c_struct model) {
    return request<server::ThreadMessageGetResult_c_struct>("threadMessageGet", model.toJSON());
}

server::ThreadMessagesGetResult_c_struct ServerApi::threadMessagesGet(server::ThreadMessagesGetModel_c_struct model) {
    return request<server::ThreadMessagesGetResult_c_struct>("threadMessagesGet", model.toJSON());
}

void ServerApi::threadMessageUpdate(server::ThreadMessageUpdateModel_c_struct model) {
    request("threadMessageUpdate", model.toJSON());
}

template<class T> T ServerApi::request(const std::string& method, Poco::JSON::Object::Ptr params) {
    return T::fromJSON(_gateway->request("thread." + method, params));
}

Poco::Dynamic::Var ServerApi::request(const std::string& method, Poco::JSON::Object::Ptr params) {
    return _gateway->request("thread." + method, params);
}
