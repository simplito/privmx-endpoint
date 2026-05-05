/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/endpoint/inbox/ServerApi.hpp>
#include <privmx/utils/JsonHelper.hpp>

using namespace privmx::endpoint::inbox;

ServerApi::ServerApi(const privfs::RpcGateway::Ptr gateway) : thread::ServerApi(gateway), store::ServerApi(gateway), _gateway(gateway) {}

server::InboxCreateResult ServerApi::inboxCreate(server::InboxCreateModel model) {
    return request<server::InboxCreateResult>("inboxCreate", model.toJSON());
}

void ServerApi::inboxUpdate(server::InboxUpdateModel model) {
    request("inboxUpdate", model.toJSON());
}

server::InboxGetResult ServerApi::inboxGet(server::InboxGetModel model) {
    return request<server::InboxGetResult>("inboxGet", model.toJSON());
}

server::InboxGetPublicViewResult ServerApi::inboxGetPublicView(server::InboxGetModel model) {
    return request<server::InboxGetPublicViewResult>("inboxGetPublicView", model.toJSON());
}

server::InboxListResult ServerApi::inboxList(server::InboxListModel model) {
    return request<server::InboxListResult>("inboxList", model.toJSON());
}

void ServerApi::inboxSend(server::InboxSendModel model) {
    request("inboxSend", model.toJSON());
}

void ServerApi::inboxDelete(server::InboxDeleteModel model) {
    request("inboxDelete", model.toJSON());
}

template<class T> T ServerApi::request(const std::string& method, Poco::JSON::Object::Ptr params) {
    return T::fromJSON(_gateway->request("inbox." + method, params));
}

Poco::Dynamic::Var ServerApi::request(const std::string& method, Poco::JSON::Object::Ptr params) {
    return _gateway->request("inbox." + method, params);
}
