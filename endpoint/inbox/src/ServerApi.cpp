/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/endpoint/inbox/ServerApi.hpp>

using namespace privmx::endpoint::inbox;

ServerApi::ServerApi(const privfs::RpcGateway::Ptr gateway) : thread::ServerApi(gateway), store::ServerApi(gateway), _gateway(gateway) {}

server::InboxCreateResult ServerApi::inboxCreate(server::InboxCreateModel model) {
    return request<server::InboxCreateResult>("inboxCreate", model);
}

void ServerApi::inboxUpdate(server::InboxUpdateModel model) {
    request("inboxUpdate", model);
}

server::InboxGetResult ServerApi::inboxGet(server::InboxGetModel model) {
    return request<server::InboxGetResult>("inboxGet", model);
}

server::InboxGetPublicViewResult ServerApi::inboxGetPublicView(server::InboxGetModel model) {
    return request<server::InboxGetPublicViewResult>("inboxGetPublicView", model);
}

server::InboxListResult ServerApi::inboxList(server::InboxListModel model) {
    return request<server::InboxListResult>("inboxList", model);
}

void ServerApi::inboxSend(server::InboxSendModel model) {
    request("inboxSend", model);
}

void ServerApi::inboxDelete(server::InboxDeleteModel model) {
    request("inboxDelete", model);
}

template<class T> T ServerApi::request(const std::string method, const Poco::JSON::Object::Ptr params) {  //only typed object
    return privmx::utils::TypedObjectFactory::createObjectFromVar<T>(_gateway->request("inbox." + method, params));
}

Poco::Dynamic::Var ServerApi::request(const std::string method, const Poco::JSON::Object::Ptr params) {  //var
    return _gateway->request("inbox." + method, params);
}