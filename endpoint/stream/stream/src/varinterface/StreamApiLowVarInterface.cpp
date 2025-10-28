/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/
#include <Poco/JSON/Parser.h>
#include "privmx/endpoint/core/TypesMacros.hpp"
#include "privmx/endpoint/stream/varinterface/StreamApiLowVarInterface.hpp"

#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/core/varinterface/VarInterfaceUtil.hpp"
#include "privmx/endpoint/stream/DynamicTypes.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::stream;

std::map<StreamApiLowVarInterface::METHOD, Poco::Dynamic::Var (StreamApiLowVarInterface::*)(const Poco::Dynamic::Var&)>
    StreamApiLowVarInterface::methodMap = {
    {Create, &StreamApiLowVarInterface::create},
    {GetTurnCredentials, &StreamApiLowVarInterface::getTurnCredentials},
    {CreateStreamRoom, &StreamApiLowVarInterface::createStreamRoom},
    {UpdateStreamRoom, &StreamApiLowVarInterface::updateStreamRoom},
    {ListStreamRooms, &StreamApiLowVarInterface::listStreamRooms},
    {GetStreamRoom, &StreamApiLowVarInterface::getStreamRoom},
    {DeleteStreamRoom, &StreamApiLowVarInterface::deleteStreamRoom},

    {SubscribeFor, &StreamApiLowVarInterface::subscribeFor},
    {UnsubscribeFrom, &StreamApiLowVarInterface::unsubscribeFrom},
    {BuildSubscriptionQuery, &StreamApiLowVarInterface::buildSubscriptionQuery},

    {ListStreams, &StreamApiLowVarInterface::listStreams},
    {JoinRoom, &StreamApiLowVarInterface::joinRoom},
    {LeaveRoom, &StreamApiLowVarInterface::leaveRoom},

    {CreateStream, &StreamApiLowVarInterface::createStream},
    {PublishStream, &StreamApiLowVarInterface::publishStream},
    {UnpublishStream, &StreamApiLowVarInterface::unpublishStream},

    {SubscribeToRemoteStream, &StreamApiLowVarInterface::subscribeToRemoteStream},
    {SubscribeToRemoteStreams, &StreamApiLowVarInterface::subscribeToRemoteStreams},
    {ModifyRemoteStreamSubscription, &StreamApiLowVarInterface::modifyRemoteStreamSubscription},
    {UnsubscribeFromRemoteStream, &StreamApiLowVarInterface::unsubscribeFromRemoteStream},
    {UnsubscribeFromRemoteStreams, &StreamApiLowVarInterface::unsubscribeFromRemoteStreams},
    {Trickle, &StreamApiLowVarInterface::keyManagement},
    {KeyManagement, &StreamApiLowVarInterface::keyManagement}
};
Poco::Dynamic::Var StreamApiLowVarInterface::create(const Poco::Dynamic::Var& args) {
    core::VarInterfaceUtil::validateAndExtractArray(args, 0);
    _streamApi = StreamApiLow::create(_connection, _eventApi);
    return {};
}

Poco::Dynamic::Var StreamApiLowVarInterface::getTurnCredentials(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 0);
    auto result = _streamApi.getTurnCredentials();
    return _serializer.serialize(result);
}

Poco::Dynamic::Var StreamApiLowVarInterface::subscribeFor(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto subscriptionQueries = _deserializer.deserializeVector<std::string>(argsArr->get(0), "subscriptionQueries");
    auto result = _streamApi.subscribeFor(subscriptionQueries);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var StreamApiLowVarInterface::unsubscribeFrom(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto subscriptionIds = _deserializer.deserializeVector<std::string>(argsArr->get(0), "subscriptionIds");
    _streamApi.unsubscribeFrom(subscriptionIds);
    return {};
}

Poco::Dynamic::Var StreamApiLowVarInterface::buildSubscriptionQuery(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 3);
    auto eventType = _deserializer.deserialize<stream::EventType>(argsArr->get(0), "eventType");
    auto selectorType = _deserializer.deserialize<stream::EventSelectorType>(argsArr->get(1), "selectorType");
    auto selectorId = _deserializer.deserialize<std::string>(argsArr->get(2), "selectorId");
    auto result = _streamApi.buildSubscriptionQuery(eventType, selectorType, selectorId);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var StreamApiLowVarInterface::createStreamRoom(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 6);
    auto contextId = _deserializer.deserialize<std::string>(argsArr->get(0), "contextId");
    auto users = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(1), "users");
    auto managers = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(2), "managers");
    auto publicMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(3), "publicMeta");
    auto privateMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(4), "privateMeta");
    auto policies = _deserializer.deserializeOptional<core::ContainerPolicy>(argsArr->get(5), "policies");
    auto result = _streamApi.createStreamRoom(contextId, users, managers, publicMeta, privateMeta, policies);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var StreamApiLowVarInterface::updateStreamRoom(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 9);
    auto inboxId = _deserializer.deserialize<std::string>(argsArr->get(0), "inboxId");
    auto users = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(1), "users");
    auto managers = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(2), "managers");
    auto publicMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(3), "publicMeta");
    auto privateMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(4), "privateMeta");
    auto version = _deserializer.deserialize<int64_t>(argsArr->get(5), "version");
    auto force = _deserializer.deserialize<bool>(argsArr->get(6), "force");
    auto forceGenerateNewKey = _deserializer.deserialize<bool>(argsArr->get(7), "forceGenerateNewKey");
    auto policies = _deserializer.deserializeOptional<core::ContainerPolicy>(argsArr->get(8), "policies");
    _streamApi.updateStreamRoom(inboxId, users, managers, publicMeta, privateMeta, version, force,
                          forceGenerateNewKey, policies);
    return {};
}

Poco::Dynamic::Var StreamApiLowVarInterface::listStreamRooms(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto contextId = _deserializer.deserialize<std::string>(argsArr->get(0), "contextId");
    auto pagingQuery = _deserializer.deserialize<core::PagingQuery>(argsArr->get(1), "pagingQuery");
    auto result = _streamApi.listStreamRooms(contextId, pagingQuery);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var StreamApiLowVarInterface::getStreamRoom(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto streamRoomId = _deserializer.deserialize<std::string>(argsArr->get(0), "streamRoomId");
    auto result = _streamApi.getStreamRoom(streamRoomId);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var StreamApiLowVarInterface::deleteStreamRoom(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto streamRoomId = _deserializer.deserialize<std::string>(argsArr->get(0), "streamRoomId");
    _streamApi.deleteStreamRoom(streamRoomId);
    return {};
}


Poco::Dynamic::Var StreamApiLowVarInterface::listStreams(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto streamRoomId = _deserializer.deserialize<std::string>(argsArr->get(0), "streamRoomId");
    auto result = _streamApi.listStreams(streamRoomId);
    return _serializer.serialize(result);
}
Poco::Dynamic::Var StreamApiLowVarInterface::joinRoom(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto streamRoomId = _deserializer.deserialize<std::string>(argsArr->get(0), "streamRoomId");
    _streamApi.joinRoom(streamRoomId, getWebRtcInterface());
    return {};
}
Poco::Dynamic::Var StreamApiLowVarInterface::leaveRoom(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto streamRoomId = _deserializer.deserialize<std::string>(argsArr->get(0), "streamRoomId");
    _streamApi.leaveRoom(streamRoomId);
    return {};
}

Poco::Dynamic::Var StreamApiLowVarInterface::createStream(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto streamRoomId = _deserializer.deserialize<std::string>(argsArr->get(0), "streamRoomId");
    auto streamHandle = _deserializer.deserialize<int64_t>(argsArr->get(1), "streamHandle");
    _streamApi.createStream(streamRoomId, streamHandle);
    return {};
}
Poco::Dynamic::Var StreamApiLowVarInterface::publishStream(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto streamHandle = _deserializer.deserialize<int64_t>(argsArr->get(1), "streamHandle");
    _streamApi.publishStream(streamHandle);
    return {};
}
Poco::Dynamic::Var StreamApiLowVarInterface::unpublishStream(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto streamHandle = _deserializer.deserialize<int64_t>(argsArr->get(0), "streamHandle");
    _streamApi.unpublishStream(streamHandle);
    return {};
}

Poco::Dynamic::Var StreamApiLowVarInterface::subscribeToRemoteStream(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 4);
    auto streamRoomId = _deserializer.deserialize<std::string>(argsArr->get(0), "streamRoomId");
    auto streamId = _deserializer.deserialize<int64_t>(argsArr->get(1), "streamId");
    auto tracksId = _deserializer.deserializeOptionalVector<int64_t>(argsArr->get(2), "tracksIds");
    auto options = _deserializer.deserialize<Settings>(argsArr->get(3), "options");
    _streamApi.subscribeToRemoteStream(streamRoomId, streamId, tracksId, options);
    return {};
}
Poco::Dynamic::Var StreamApiLowVarInterface::subscribeToRemoteStreams(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 3);
    auto streamRoomId = _deserializer.deserialize<std::string>(argsArr->get(0), "streamRoomId");
    auto streamsId = _deserializer.deserializeVector<int64_t>(argsArr->get(1), "streamsId");
    auto options = _deserializer.deserialize<Settings>(argsArr->get(2), "options");
    _streamApi.subscribeToRemoteStreams(streamRoomId, streamsId, options);
    return {};
}
Poco::Dynamic::Var StreamApiLowVarInterface::modifyRemoteStreamSubscription(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 5);
    auto streamRoomId = _deserializer.deserialize<std::string>(argsArr->get(0), "streamRoomId");
    auto streamId = _deserializer.deserialize<int64_t>(argsArr->get(1), "streamId");
    auto options = _deserializer.deserialize<Settings>(argsArr->get(2), "options");
    auto tracksIdsToAdd = _deserializer.deserializeOptionalVector<int64_t>(argsArr->get(3), "tracksIdsToAdd");
    auto tracksIdsToRemove = _deserializer.deserializeOptionalVector<int64_t>(argsArr->get(4), "tracksIdsToRemove");
    _streamApi.modifyRemoteStreamSubscription(streamRoomId, streamId, options, tracksIdsToAdd, tracksIdsToRemove);
    return {};
}
Poco::Dynamic::Var StreamApiLowVarInterface::unsubscribeFromRemoteStream(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto streamRoomId = _deserializer.deserialize<std::string>(argsArr->get(0), "streamRoomId");
    auto streamId = _deserializer.deserialize<int64_t>(argsArr->get(1), "streamId");
    auto options = _deserializer.deserialize<Settings>(argsArr->get(2), "options");
    _streamApi.unsubscribeFromRemoteStream(streamRoomId, streamId);
    return {};
}
Poco::Dynamic::Var StreamApiLowVarInterface::unsubscribeFromRemoteStreams(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto streamRoomId = _deserializer.deserialize<std::string>(argsArr->get(0), "streamRoomId");
    auto streamsId = _deserializer.deserializeVector<int64_t>(argsArr->get(1), "streamsId");
    _streamApi.unsubscribeFromRemoteStreams(streamRoomId, streamsId);
    return {};
}

Poco::Dynamic::Var StreamApiLowVarInterface::trickle(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto sessionId = _deserializer.deserialize<int64_t>(argsArr->get(0), "sessionId");
    auto serializedRtcCandidate = _deserializer.deserialize<std::string>(argsArr->get(1), "candidate");
    Poco::JSON::Parser parser;
    auto iceCandidate {utils::TypedObjectFactory::createObjectFromVar<dynamic::RTCIceCandidate>(parser.parse(serializedRtcCandidate))};
    _streamApi.trickle(sessionId, iceCandidate);
    return {};
}

Poco::Dynamic::Var StreamApiLowVarInterface::acceptOfferOnReconfigure(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto sessionId = _deserializer.deserialize<int64_t>(argsArr->get(0), "sessionId");
    auto jsep = _deserializer.deserialize<stream::SdpWithTypeModel>(argsArr->get(1), "jsep");
    _streamApi.acceptOfferOnReconfigure(sessionId, jsep);
    return {};
}

Poco::Dynamic::Var StreamApiLowVarInterface::keyManagement(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto streamRoomId = _deserializer.deserialize<std::string>(argsArr->get(0), "streamRoomId");
    auto disable = _deserializer.deserialize<bool>(argsArr->get(1), "disable");
    _streamApi.keyManagement(streamRoomId, disable);
    return {};
}

Poco::Dynamic::Var StreamApiLowVarInterface::exec(METHOD method, const Poco::Dynamic::Var& args) {
    auto it = methodMap.find(method);
    if (it == methodMap.end()) {
        throw core::InvalidMethodException();
    }
    return (*this.*(it->second))(args);
}


std::shared_ptr<WebRTCInterface> StreamApiLowVarInterface:: getWebRtcInterface() {
    return _webRtcInterface;
}

void StreamApiLowVarInterface::setWebRtcInterface(std::shared_ptr<WebRTCInterface> webRtcInterface) {
    std::unique_lock lock(_mutex);
    _webRtcInterface = webRtcInterface;
}

int64_t StreamApiLowVarInterface::getWebRtcInterfaceRawPtr() {
    return (int64_t)(_webRtcInterface.get());
}