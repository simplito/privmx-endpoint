/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/
#include "privmx/endpoint/stream/varinterface/StreamApiLowVarInterface.hpp"

#include <Poco/JSON/Parser.h>

#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/core/varinterface/VarInterfaceUtil.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::stream;

std::map<StreamApiLowVarInterface::METHOD, Poco::Dynamic::Var (StreamApiLowVarInterface::*)(const Poco::Dynamic::Var&)>
    StreamApiLowVarInterface::methodMap = {
        {Create, &StreamApiLowVarInterface::create},
        {GetTurnCredentials, &StreamApiLowVarInterface::getTurnCredentials},
        {CreateStreamRoom, &StreamApiLowVarInterface::createStreamRoom},
        {UpdateStreamRoom, &StreamApiLowVarInterface::updateStreamRoom},
        {RotateStreamRoomKeys, &StreamApiLowVarInterface::rotateStreamRoomKeys},
        {ListStreamRooms, &StreamApiLowVarInterface::listStreamRooms},
        {GetStreamRoom, &StreamApiLowVarInterface::getStreamRoom},
        {DeleteStreamRoom, &StreamApiLowVarInterface::deleteStreamRoom},

        {SubscribeFor, &StreamApiLowVarInterface::subscribeFor},
        {UnsubscribeFrom, &StreamApiLowVarInterface::unsubscribeFrom},
        {BuildSubscriptionQuery, &StreamApiLowVarInterface::buildSubscriptionQuery},

        {ListStreams, &StreamApiLowVarInterface::listStreams},
        {JoinStreamRoom, &StreamApiLowVarInterface::joinStreamRoom},
        {JoinStreamRoomEx, &StreamApiLowVarInterface::joinStreamRoomEx},
        {LeaveStreamRoom, &StreamApiLowVarInterface::leaveStreamRoom},
        {CreateStream, &StreamApiLowVarInterface::createStream},
        {PublishStream, &StreamApiLowVarInterface::publishStream},
        {UpdateStream, &StreamApiLowVarInterface::updateStream},
        {RemoveStream, &StreamApiLowVarInterface::removeStream},

        {CreateSubscriberStream, &StreamApiLowVarInterface::createSubscriberStream},
        {UpdateSubscriberStream, &StreamApiLowVarInterface::updateSubscriberStream},
        {RemoveSubscriberStream, &StreamApiLowVarInterface::removeSubscriberStream},

        {Trickle, &StreamApiLowVarInterface::trickle},
        {ListStreamRoomParticipants, &StreamApiLowVarInterface::listStreamRoomParticipants},

        {EncryptDataChannelMessage, &StreamApiLowVarInterface::encryptDataChannelMessage},
        {DecryptDataChannelMessage, &StreamApiLowVarInterface::decryptDataChannelMessage}
};
Poco::Dynamic::Var StreamApiLowVarInterface::create(const Poco::Dynamic::Var& args) {
    core::VarInterfaceUtil::validateAndExtractArray(args, 0);
    _streamApi = StreamApiLow::create(_connection, _groupApi);
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
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 8);
    auto contextId = _deserializer.deserialize<std::string>(argsArr->get(0), "contextId");
    auto users = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(1), "users");
    auto managers = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(2), "managers");
    auto publicMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(3), "publicMeta");
    auto privateMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(4), "privateMeta");
    auto policies = _deserializer.deserializeOptional<core::ContainerPolicyWithoutItem>(argsArr->get(5), "policies");
    auto emptyRoomTtl = _deserializer.deserializeOptional<int64_t>(argsArr->get(6), "emptyRoomTtl");
    auto groups = _deserializer.deserializeVector<core::GroupGrantWithKey>(argsArr->get(7), "groups");
    auto result = _streamApi.createStreamRoom(
        contextId, users, managers, publicMeta, privateMeta, policies, emptyRoomTtl, groups
    );
    return _serializer.serialize(result);
}

Poco::Dynamic::Var StreamApiLowVarInterface::updateStreamRoom(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 10);
    auto inboxId = _deserializer.deserialize<std::string>(argsArr->get(0), "inboxId");
    auto users = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(1), "users");
    auto managers = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(2), "managers");
    auto publicMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(3), "publicMeta");
    auto privateMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(4), "privateMeta");
    auto version = _deserializer.deserialize<int64_t>(argsArr->get(5), "version");
    auto force = _deserializer.deserialize<bool>(argsArr->get(6), "force");
    auto forceGenerateNewKey = _deserializer.deserialize<bool>(argsArr->get(7), "forceGenerateNewKey");
    auto policies = _deserializer.deserializeOptional<core::ContainerPolicyWithoutItem>(argsArr->get(8), "policies");
    auto groups = _deserializer.deserializeVector<core::GroupGrantWithKey>(argsArr->get(9), "groups");
    _streamApi.updateStreamRoom(
        inboxId, users, managers, publicMeta, privateMeta, version, force, forceGenerateNewKey, policies, groups
    );
    return {};
}

Poco::Dynamic::Var StreamApiLowVarInterface::rotateStreamRoomKeys(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 6);
    auto streamRoomId = _deserializer.deserialize<std::string>(argsArr->get(0), "streamRoomId");
    auto users = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(1), "users");
    auto managers = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(2), "managers");
    auto version = _deserializer.deserialize<int64_t>(argsArr->get(3), "version");
    auto force = _deserializer.deserialize<bool>(argsArr->get(4), "force");
    auto groups = _deserializer.deserializeVector<core::GroupGrantWithKey>(argsArr->get(5), "groups");
    _streamApi.rotateStreamRoomKeys(streamRoomId, users, managers, version, force, groups);
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
Poco::Dynamic::Var StreamApiLowVarInterface::joinStreamRoom(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto streamRoomId = _deserializer.deserialize<std::string>(argsArr->get(0), "streamRoomId");
    _streamApi.joinStreamRoom(streamRoomId, getWebRtcInterface());
    return {};
}

Poco::Dynamic::Var StreamApiLowVarInterface::joinStreamRoomEx(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto streamRoomId = _deserializer.deserialize<std::string>(argsArr->get(0), "streamRoomId");
    auto webRtc = _deserializer.deserializePointer<WebRTCInterface>(argsArr->get(1), "webRtc");
    _streamApi.joinStreamRoom(streamRoomId, *webRtc);
    return {};
}
Poco::Dynamic::Var StreamApiLowVarInterface::leaveStreamRoom(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto streamRoomId = _deserializer.deserialize<std::string>(argsArr->get(0), "streamRoomId");
    _streamApi.leaveStreamRoom(streamRoomId);
    return {};
}

Poco::Dynamic::Var StreamApiLowVarInterface::listStreamRoomParticipants(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto streamRoomId = _deserializer.deserialize<std::string>(argsArr->get(0), "streamRoomId");
    auto result = _streamApi.listStreamRoomParticipants(streamRoomId);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var StreamApiLowVarInterface::createStream(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto streamRoomId = _deserializer.deserialize<std::string>(argsArr->get(0), "streamRoomId");
    auto result = _streamApi.createStream(streamRoomId);
    return _serializer.serialize(result);
}
Poco::Dynamic::Var StreamApiLowVarInterface::publishStream(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto streamHandle = _deserializer.deserialize<int64_t>(argsArr->get(0), "streamHandle");
    auto result = _streamApi.publishStream(streamHandle);
    return _serializer.serialize(result);
}
Poco::Dynamic::Var StreamApiLowVarInterface::updateStream(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto streamHandle = _deserializer.deserialize<int64_t>(argsArr->get(0), "streamHandle");
    auto result = _streamApi.updateStream(streamHandle);
    return _serializer.serialize(result);
}
Poco::Dynamic::Var StreamApiLowVarInterface::removeStream(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto streamHandle = _deserializer.deserialize<int64_t>(argsArr->get(0), "streamHandle");
    _streamApi.removeStream(streamHandle);
    return {};
}

Poco::Dynamic::Var StreamApiLowVarInterface::createSubscriberStream(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto streamRoomId = _deserializer.deserialize<std::string>(argsArr->get(0), "streamRoomId");
    auto subscriptions = _deserializer.deserializeVector<StreamSubscription>(argsArr->get(1), "subscriptions");
    return _streamApi.createSubscriberStream(streamRoomId, subscriptions);
}
Poco::Dynamic::Var StreamApiLowVarInterface::updateSubscriberStream(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 3);
    auto subscriptionHandle = _deserializer.deserialize<SubscriberStreamHandle>(argsArr->get(0), "subscriptionHandle");
    auto subscriptionsToAdd = _deserializer.deserializeVector<StreamSubscription>(
        argsArr->get(1), "subscriptionsToAdd"
    );
    auto subscriptionsToRemove = _deserializer.deserializeVector<StreamSubscription>(
        argsArr->get(2), "subscriptionsToRemove"
    );
    _streamApi.updateSubscriberStream(subscriptionHandle, subscriptionsToAdd, subscriptionsToRemove);
    return {};
}
Poco::Dynamic::Var StreamApiLowVarInterface::removeSubscriberStream(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto subscriptionHandle = _deserializer.deserialize<SubscriberStreamHandle>(argsArr->get(0), "subscriptionHandle");
    _streamApi.removeSubscriberStream(subscriptionHandle);
    return {};
}

Poco::Dynamic::Var StreamApiLowVarInterface::trickle(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto sessionId = _deserializer.deserialize<int64_t>(argsArr->get(0), "sessionId");
    auto serializedRtcCandidate = _deserializer.deserialize<std::string>(argsArr->get(1), "candidate");
    _streamApi.trickle(sessionId, serializedRtcCandidate);
    return {};
}

Poco::Dynamic::Var StreamApiLowVarInterface::setNewOfferOnReconfigure(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto sessionId = _deserializer.deserialize<int64_t>(argsArr->get(0), "sessionId");
    auto jsep = _deserializer.deserialize<stream::SdpWithTypeModel>(argsArr->get(1), "jsep");
    _streamApi.setNewOfferOnReconfigure(sessionId, jsep);
    return {};
}
Poco::Dynamic::Var StreamApiLowVarInterface::encryptDataChannelMessage(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto streamRoomId = _deserializer.deserialize<std::string>(argsArr->get(0), "streamRoomId");
    auto plainMessage = _deserializer.deserialize<stream::DataChannelMessage>(argsArr->get(1), "plainMessage");
    auto result = _streamApi.encryptDataChannelMessage(streamRoomId, plainMessage);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var StreamApiLowVarInterface::decryptDataChannelMessage(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 3);
    auto streamRoomId = _deserializer.deserialize<std::string>(argsArr->get(0), "streamRoomId");
    auto remoteStreamId = _deserializer.deserialize<std::string>(argsArr->get(1), "remoteStreamId");
    auto encryptedData = _deserializer.deserialize<core::Buffer>(argsArr->get(2), "encryptedData");
    auto result = _streamApi.decryptDataChannelMessage(streamRoomId, remoteStreamId, encryptedData);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var StreamApiLowVarInterface::exec(METHOD method, const Poco::Dynamic::Var& args) {
    auto it = methodMap.find(method);
    if (it == methodMap.end()) {
        throw core::InvalidMethodException("method=" + std::to_string((int64_t)method));
    }
    return (*this.*(it->second))(args);
}

std::shared_ptr<WebRTCInterface> StreamApiLowVarInterface::getWebRtcInterface() {
    return _webRtcInterface;
}

void StreamApiLowVarInterface::setWebRtcInterface(std::shared_ptr<WebRTCInterface> webRtcInterface) {
    std::unique_lock lock(_mutex);
    _webRtcInterface = webRtcInterface;
}

int64_t StreamApiLowVarInterface::getWebRtcInterfaceRawPtr() {
    return (int64_t)(_webRtcInterface.get());
}