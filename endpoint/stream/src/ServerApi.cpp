/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/stream/ServerApi.hpp"
#include "privmx/endpoint/stream/StreamException.hpp"

using namespace privmx::endpoint::stream;
using namespace privmx::endpoint;

ServerApi::ServerApi(privmx::privfs::RpcGateway::Ptr gateway) : _gateway(gateway) {}


server::StreamRoomCreateResult ServerApi::streamRoomCreate(server::StreamRoomCreateModel model)  {
    return request<server::StreamRoomCreateResult>("streamRoomCreate", model);
}

void ServerApi::streamRoomUpdate(server::StreamRoomUpdateModel model) {
    request("streamRoomUpdate", model);
}

server::StreamRoomListResult ServerApi::streamRoomList(server::StreamRoomListModel model)  {
    return request<server::StreamRoomListResult>("streamRoomList", model);
}

server::StreamRoomGetResult ServerApi::streamRoomGet(server::StreamRoomGetModel model)  {
    return request<server::StreamRoomGetResult>("streamRoomGet", model);
}

void ServerApi::streamRoomDelete(server::StreamRoomDeleteModel model) {
    request("streamRoomDelete", model);
}

server::StreamGetTurnCredentialsResult ServerApi::streamGetTurnCredentials(server::StreamGetTurnCredentialsModel model) {
    return requestWS<server::StreamGetTurnCredentialsResult>("streamGetTurnCredentials", model);
}

server::StreamListResult ServerApi::streamList(server::StreamListModel model)  {
    return requestWS<server::StreamListResult>("streamList", model);
}

server::StreamPublishResult ServerApi::streamPublish(server::StreamPublishModel model)  {
    return requestWS<server::StreamPublishResult>("streamPublish", model);
}
server::StreamJoinResult ServerApi::streamJoin(server::StreamJoinModel model)  {
    return requestWS<server::StreamJoinResult>("streamJoin", model);
}

void ServerApi::streamAcceptOffer(server::StreamAcceptOfferModel model) {
    auto a = requestWS("streamAcceptOffer", model);
    std::cout << privmx::utils::Utils::stringifyVar(a, true) << std::endl;
    return;
}

void ServerApi::streamUnpublish(server::StreamUnpublishModel model) {
    requestWS("streamUnpublish", model);
}

void ServerApi::streamLeave(server::StreamLeaveModel model) {
    requestWS("streamLeave", model);
}

server::ContextGetUserResult ServerApi::contextGetUsers(server::ContextGetUsersModel model) {
    return privmx::utils::TypedObjectFactory::createObjectFromVar<server::ContextGetUserResult>(_gateway->request("context.contextGetUsers", model));
}

template<class T> T ServerApi::request(const std::string& method, Poco::JSON::Object::Ptr params) {  //only typed object
    return privmx::utils::TypedObjectFactory::createObjectFromVar<T>(_gateway->request("stream." + method, params));
}

Poco::Dynamic::Var ServerApi::request(const std::string& method, Poco::JSON::Object::Ptr params) {  //var
    return _gateway->request("stream." + method, params);
}

template<class T> T ServerApi::requestWS(const std::string& method, Poco::JSON::Object::Ptr params) {  //only typed object
    return privmx::utils::TypedObjectFactory::createObjectFromVar<T>(_gateway->request("stream." + method, params, {.channel_type=privmx::rpc::ChannelType::WEBSOCKET}));
}

Poco::Dynamic::Var ServerApi::requestWS(const std::string& method, Poco::JSON::Object::Ptr params) {  //var
    return _gateway->request("stream." + method, params, {.channel_type=privmx::rpc::ChannelType::WEBSOCKET});
}