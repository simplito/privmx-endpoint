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

server::InboxCreateResult_c_struct ServerApi::inboxCreate(server::InboxCreateModel_c_struct model) {
    return request<server::InboxCreateResult_c_struct>("inboxCreate", model.toJSON());
}

void ServerApi::inboxUpdate(server::InboxUpdateModel_c_struct model) {
    request("inboxUpdate", model.toJSON());
}

server::InboxGetResult_c_struct ServerApi::inboxGet(server::InboxGetModel_c_struct model) {
    return request<server::InboxGetResult_c_struct>("inboxGet", model.toJSON());
}

server::InboxGetPublicViewResult_c_struct ServerApi::inboxGetPublicView(server::InboxGetModel_c_struct model) {
    return request<server::InboxGetPublicViewResult_c_struct>("inboxGetPublicView", model.toJSON());
}

server::InboxListResult_c_struct ServerApi::inboxList(server::InboxListModel_c_struct model) {
    return request<server::InboxListResult_c_struct>("inboxList", model.toJSON());
}

void ServerApi::inboxSend(server::InboxSendModel_c_struct model) {
    request("inboxSend", model.toJSON());
}

void ServerApi::inboxDelete(server::InboxDeleteModel_c_struct model) {
    request("inboxDelete", model.toJSON());
}

template<class T> T ServerApi::request(const std::string& method, Poco::JSON::Object::Ptr params) {
    return T::fromJSON(_gateway->request("inbox." + method, params));
}

Poco::Dynamic::Var ServerApi::request(const std::string& method, Poco::JSON::Object::Ptr params) {
    return _gateway->request("inbox." + method, params);
}
