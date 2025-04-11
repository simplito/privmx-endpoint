/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/stream/varinterface/StreamApiLowVarInterface.hpp"

#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/core/varinterface/VarInterfaceUtil.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::stream;

std::map<StreamApiLowVarInterface::METHOD, Poco::Dynamic::Var (StreamApiLowVarInterface::*)(const Poco::Dynamic::Var&)>
    StreamApiLowVarInterface::methodMap = {{Create, &StreamApiLowVarInterface::create},
                                       {GetTurnCredentials, &StreamApiLowVarInterface::getTurnCredentials},
                                       {CreateStreamRoom, &StreamApiLowVarInterface::createStreamRoom},
                                       {UpdateStreamRoom, &StreamApiLowVarInterface::updateStreamRoom},
                                       {ListStreamRooms, &StreamApiLowVarInterface::listStreamRooms},
                                       {GetStreamRoom, &StreamApiLowVarInterface::getStreamRoom},
                                       {DeleteStreamRoom, &StreamApiLowVarInterface::deleteStreamRoom},
                                       {CreateStream, &StreamApiLowVarInterface::createStream},
                                       {PublishStream, &StreamApiLowVarInterface::publishStream},
                                       {JoinStream, &StreamApiLowVarInterface::joinStream},
                                       {ListStreams, &StreamApiLowVarInterface::listStreams},
                                       {UnpublishStream, &StreamApiLowVarInterface::unpublishStream},
                                       {LeaveStream, &StreamApiLowVarInterface::leaveStream},
                                       {KeyManagement, &StreamApiLowVarInterface::keyManagement}};

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

Poco::Dynamic::Var StreamApiLowVarInterface::createStream(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 3);
    auto streamRoomId = _deserializer.deserialize<std::string>(argsArr->get(0), "streamRoomId");
    auto localStreamId = _deserializer.deserialize<int64_t>(argsArr->get(1), "localStreamId");
    auto webRtcInt = _deserializer.deserialize<int64_t>(argsArr->get(2), "webRtc");
    std::shared_ptr<WebRTCInterface>* webRtcPtr = (std::shared_ptr<WebRTCInterface>*)webRtcInt;
    auto result = _streamApi.createStream(streamRoomId, localStreamId, (*webRtcPtr));
    return _serializer.serialize(result);
}

Poco::Dynamic::Var StreamApiLowVarInterface::publishStream(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto localStreamId = _deserializer.deserialize<int64_t>(argsArr->get(0), "localStreamId");
    _streamApi.publishStream(localStreamId);
    return {};
}

Poco::Dynamic::Var StreamApiLowVarInterface::joinStream(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 5);
    auto streamRoomId = _deserializer.deserialize<std::string>(argsArr->get(0), "streamRoomId");
    auto streamsId = _deserializer.deserializeVector<int64_t>(argsArr->get(1), "streamsId");
    auto settings = _deserializer.deserialize<Settings>(argsArr->get(2), "settings");
    auto localStreamId = _deserializer.deserialize<int64_t>(argsArr->get(3), "localStreamId");
    auto webRtcInt = _deserializer.deserialize<int64_t>(argsArr->get(4), "webRtc");
    std::shared_ptr<WebRTCInterface>* webRtcPtr = (std::shared_ptr<WebRTCInterface>*)webRtcInt;
    auto result = _streamApi.joinStream(streamRoomId, streamsId, settings, localStreamId, (*webRtcPtr));
    return _serializer.serialize(result);
}

Poco::Dynamic::Var StreamApiLowVarInterface::listStreams(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto streamRoomId = _deserializer.deserialize<std::string>(argsArr->get(0), "streamRoomId");
    auto result = _streamApi.listStreams(streamRoomId);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var StreamApiLowVarInterface::unpublishStream(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto localStreamId = _deserializer.deserialize<int64_t>(argsArr->get(0), "localStreamId");
    _streamApi.unpublishStream(localStreamId);
    return {};
}

Poco::Dynamic::Var StreamApiLowVarInterface::leaveStream(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto localStreamId = _deserializer.deserialize<int64_t>(argsArr->get(0), "localStreamId");
    _streamApi.leaveStream(localStreamId);
    return {};
}

Poco::Dynamic::Var StreamApiLowVarInterface::keyManagement(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto disable = _deserializer.deserialize<bool>(argsArr->get(0), "disable");
    _streamApi.keyManagement(disable);
    return {};
}

Poco::Dynamic::Var StreamApiLowVarInterface::exec(METHOD method, const Poco::Dynamic::Var& args) {
    auto it = methodMap.find(method);
    if (it == methodMap.end()) {
        throw core::InvalidMethodException();
    }
    return (*this.*(it->second))(args);
}
