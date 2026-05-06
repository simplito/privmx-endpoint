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

server::ThreadCreateResult ServerApi::threadCreate(server::ThreadCreateModel model) {
    return request<server::ThreadCreateResult>("threadCreate", model.toJSON());
}

void ServerApi::threadUpdate(server::ThreadUpdateModel model) {
    request("threadUpdate", model.toJSON());
}

void ServerApi::threadDelete(server::ThreadDeleteModel model) {
    request("threadDelete", model.toJSON());
}

server::ThreadGetResult ServerApi::threadGet(server::ThreadGetModel model) {
    return request<server::ThreadGetResult>("threadGet", model.toJSON());
}

server::ThreadListResult ServerApi::threadList(server::ThreadListModel model) {
    return request<server::ThreadListResult>("threadList", model.toJSON());
}

server::ThreadMessageSendResult ServerApi::threadMessageSend(server::ThreadMessageSendModel model) {
    return request<server::ThreadMessageSendResult>("threadMessageSend", model.toJSON());
}

void ServerApi::threadMessageDelete(server::ThreadMessageDeleteModel model) {
    request("threadMessageDelete", model.toJSON());
}

server::ThreadMessageGetResult ServerApi::threadMessageGet(server::ThreadMessageGetModel model) {
    return request<server::ThreadMessageGetResult>("threadMessageGet", model.toJSON());
}

server::ThreadMessagesGetResult ServerApi::threadMessagesGet(server::ThreadMessagesGetModel model) {
    return request<server::ThreadMessagesGetResult>("threadMessagesGet", model.toJSON());
}

void ServerApi::threadMessageUpdate(server::ThreadMessageUpdateModel model) {
    request("threadMessageUpdate", model.toJSON());
}

template<class T> T ServerApi::request(const std::string& method, Poco::JSON::Object::Ptr params) {
    return T::fromJSON(_gateway->request("thread." + method, params));
}

Poco::Dynamic::Var ServerApi::request(const std::string& method, Poco::JSON::Object::Ptr params) {
    return _gateway->request("thread." + method, params);
}
