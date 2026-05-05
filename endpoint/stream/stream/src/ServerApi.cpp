/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/
#include "privmx/utils/Logger.hpp"
#include "privmx/endpoint/stream/ServerApi.hpp"
#include "privmx/endpoint/stream/StreamException.hpp"

using namespace privmx::endpoint::stream;
using namespace privmx::endpoint;

ServerApi::ServerApi(privmx::privfs::RpcGateway::Ptr gateway) : _gateway(gateway) {}

server::StreamRoomCreateResult_c_struct ServerApi::streamRoomCreate(server::StreamRoomCreateModel_c_struct model) {
    return request<server::StreamRoomCreateResult_c_struct>("streamRoomCreate", model.toJSON());
}

void ServerApi::streamRoomUpdate(server::StreamRoomUpdateModel_c_struct model) {
    request("streamRoomUpdate", model.toJSON());
}

server::StreamRoomListResult_c_struct ServerApi::streamRoomList(server::StreamRoomListModel_c_struct model) {
    return request<server::StreamRoomListResult_c_struct>("streamRoomList", model.toJSON());
}

server::StreamRoomGetResult_c_struct ServerApi::streamRoomGet(server::StreamRoomGetModel_c_struct model) {
    return request<server::StreamRoomGetResult_c_struct>("streamRoomGet", model.toJSON());
}

void ServerApi::streamRoomDelete(server::StreamRoomDeleteModel_c_struct model) {
    request("streamRoomDelete", model.toJSON());
}

server::StreamGetTurnCredentialsResult_c_struct ServerApi::streamGetTurnCredentials() {
    return requestWS<server::StreamGetTurnCredentialsResult_c_struct>("streamGetTurnCredentials", Poco::JSON::Object::Ptr(new Poco::JSON::Object()));
}

server::StreamListResult_c_struct ServerApi::streamList(server::StreamListModel_c_struct model) {
    return requestWS<server::StreamListResult_c_struct>("streamList", model.toJSON());
}

server::StreamPublishResult_c_struct ServerApi::streamPublish(server::StreamPublishModel_c_struct model) {
    return requestWS<server::StreamPublishResult_c_struct>("streamPublish", model.toJSON());
}

server::StreamPublishResult_c_struct ServerApi::streamUpdate(server::StreamUpdateModel_c_struct model) {
    return requestWS<server::StreamPublishResult_c_struct>("streamUpdate", model.toJSON());
}

void ServerApi::streamAcceptOffer(server::StreamAcceptOfferModel_c_struct model) {
    requestWS("streamAcceptOffer", model.toJSON());
}

void ServerApi::streamSetNewOffer(server::StreamSetNewOfferModel_c_struct model) {
    requestWS("streamSetNewOffer", model.toJSON());
}

void ServerApi::streamUnpublish(server::StreamUnpublishModel_c_struct model) {
    requestWS("streamUnpublish", model.toJSON());
}

server::StreamsSubscribeResult_c_struct ServerApi::streamsSubscribeToRemote(server::StreamsSubscribeModel_c_struct model) {
    return requestWS<server::StreamsSubscribeResult_c_struct>("streamsSubscribeToRemote", model.toJSON());
}

server::StreamsSubscribeResult_c_struct ServerApi::streamsModifyRemoteSubscriptions(server::StreamsModifySubscriptionsModel_c_struct model) {
    return requestWS<server::StreamsSubscribeResult_c_struct>("streamsModifyRemoteSubscriptions", model.toJSON());
}

server::StreamsSubscribeResult_c_struct ServerApi::streamsUnsubscribeFromRemote(server::StreamsUnsubscribeModel_c_struct model) {
    return requestWS<server::StreamsSubscribeResult_c_struct>("streamsUnsubscribeFromRemote", model.toJSON());
}

void ServerApi::streamRoomJoin(server::StreamRoomJoinModel_c_struct model) {
    requestWS("streamRoomJoin", model.toJSON());
}

void ServerApi::streamRoomLeave(server::StreamRoomLeaveModel_c_struct model) {
    requestWS("streamRoomLeave", model.toJSON());
}

void ServerApi::streamRoomEnableRecording(server::StreamRoomRecordingModel_c_struct model) {
    requestWS("streamRoomEnableRecording", model.toJSON());
}

void ServerApi::trickle(server::StreamTrickleModel_c_struct model) {
    requestWS("streamTrickle", model.toJSON());
}

template<class T> T ServerApi::request(const std::string& method, Poco::JSON::Object::Ptr params) {
    LOG_FATAL("ServerApi::request::stream.", method, "\n", privmx::utils::Utils::stringifyVar(params, true))
    auto result = _gateway->request("stream." + method, params);
    LOG_FATAL("ServerApi::request::stream.", method, "\n", privmx::utils::Utils::stringifyVar(result, true))
    return T::fromJSON(result);
}

Poco::Dynamic::Var ServerApi::request(const std::string& method, Poco::JSON::Object::Ptr params) {
    return _gateway->request("stream." + method, params);
}
#include <privmx/utils/Logger.hpp>
template<class T> T ServerApi::requestWS(const std::string& method, Poco::JSON::Object::Ptr params) {
    LOG_INFO("ServerApi::requestWS::stream.", method, "\n Params: ", privmx::utils::Utils::stringifyVar(params, true))
    auto result = _gateway->request("stream." + method, params, {.channel_type=privmx::rpc::ChannelType::WEBSOCKET});
    LOG_INFO("ServerApi::requestWS::stream.", method, "\n Result: ", privmx::utils::Utils::stringifyVar(result, true))
    return T::fromJSON(result);
}

Poco::Dynamic::Var ServerApi::requestWS(const std::string& method, Poco::JSON::Object::Ptr params) {
    return _gateway->request("stream." + method, params, {.channel_type=privmx::rpc::ChannelType::WEBSOCKET});
}
