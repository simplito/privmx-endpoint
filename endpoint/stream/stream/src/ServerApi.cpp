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

server::StreamRoomCreateResult ServerApi::streamRoomCreate(server::StreamRoomCreateModel model) {
    return request<server::StreamRoomCreateResult>("streamRoomCreate", model.toJSON());
}

void ServerApi::streamRoomUpdate(server::StreamRoomUpdateModel model) {
    request("streamRoomUpdate", model.toJSON());
}

server::StreamRoomListResult ServerApi::streamRoomList(server::StreamRoomListModel model) {
    return request<server::StreamRoomListResult>("streamRoomList", model.toJSON());
}

server::StreamRoomGetResult ServerApi::streamRoomGet(server::StreamRoomGetModel model) {
    return request<server::StreamRoomGetResult>("streamRoomGet", model.toJSON());
}

void ServerApi::streamRoomDelete(server::StreamRoomDeleteModel model) {
    request("streamRoomDelete", model.toJSON());
}

server::StreamGetTurnCredentialsResult ServerApi::streamGetTurnCredentials() {
    return requestWS<server::StreamGetTurnCredentialsResult>("streamGetTurnCredentials", Poco::JSON::Object::Ptr(new Poco::JSON::Object()));
}

server::StreamListResult ServerApi::streamList(server::StreamListModel model) {
    return requestWS<server::StreamListResult>("streamList", model.toJSON());
}

server::StreamPublishResult ServerApi::streamPublish(server::StreamPublishModel model) {
    return requestWS<server::StreamPublishResult>("streamPublish", model.toJSON());
}

server::StreamPublishResult ServerApi::streamUpdate(server::StreamUpdateModel model) {
    return requestWS<server::StreamPublishResult>("streamUpdate", model.toJSON());
}

void ServerApi::streamAcceptOffer(server::StreamAcceptOfferModel model) {
    requestWS("streamAcceptOffer", model.toJSON());
}

void ServerApi::streamSetNewOffer(server::StreamSetNewOfferModel model) {
    requestWS("streamSetNewOffer", model.toJSON());
}

void ServerApi::streamUnpublish(server::StreamUnpublishModel model) {
    requestWS("streamUnpublish", model.toJSON());
}

server::StreamsSubscribeResult ServerApi::streamsSubscribeToRemote(server::StreamsSubscribeModel model) {
    return requestWS<server::StreamsSubscribeResult>("streamsSubscribeToRemote", model.toJSON());
}

server::StreamsSubscribeResult ServerApi::streamsModifyRemoteSubscriptions(server::StreamsModifySubscriptionsModel model) {
    return requestWS<server::StreamsSubscribeResult>("streamsModifyRemoteSubscriptions", model.toJSON());
}

server::StreamsSubscribeResult ServerApi::streamsUnsubscribeFromRemote(server::StreamsUnsubscribeModel model) {
    return requestWS<server::StreamsSubscribeResult>("streamsUnsubscribeFromRemote", model.toJSON());
}

void ServerApi::streamRoomJoin(server::StreamRoomJoinModel model) {
    requestWS("streamRoomJoin", model.toJSON());
}

void ServerApi::streamRoomLeave(server::StreamRoomLeaveModel model) {
    requestWS("streamRoomLeave", model.toJSON());
}

void ServerApi::streamRoomEnableRecording(server::StreamRoomRecordingModel model) {
    requestWS("streamRoomEnableRecording", model.toJSON());
}

void ServerApi::trickle(server::StreamTrickleModel model) {
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
