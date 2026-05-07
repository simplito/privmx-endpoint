/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/stream/StreamVarDeserializer.hpp"

#include <Poco/JSON/Array.h>
#include <Poco/JSON/Object.h>

#include <memory>

#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/core/TypeValidator.hpp"
#include "privmx/endpoint/stream/Events.hpp"
#include "privmx/endpoint/stream/ServerTypes.hpp"
#include "privmx/endpoint/stream/WebRTCInterface.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::core;

template<>
void VarDeserializer::deserialize<stream::Settings>(const Poco::Dynamic::Var& val, const std::string& name, stream::Settings& out) {
    core::TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    // empty object - for future use
    out = {};
}

template<>
void VarDeserializer::deserialize<stream::EventType>(const Poco::Dynamic::Var& val, const std::string& name, stream::EventType& out) {
    switch (val.convert<int64_t>()) {
        case stream::EventType::STREAMROOM_CREATE:
            out = stream::EventType::STREAMROOM_CREATE; return;
        case stream::EventType::STREAMROOM_UPDATE:
            out = stream::EventType::STREAMROOM_UPDATE; return;
        case stream::EventType::STREAMROOM_DELETE:
            out = stream::EventType::STREAMROOM_DELETE; return;
        case stream::EventType::STREAM_JOIN:
            out = stream::EventType::STREAM_JOIN; return;
        case stream::EventType::STREAM_LEAVE:
            out = stream::EventType::STREAM_LEAVE; return;
        case stream::EventType::STREAM_PUBLISH:
            out = stream::EventType::STREAM_PUBLISH; return;
        case stream::EventType::STREAM_UNPUBLISH:
            out = stream::EventType::STREAM_UNPUBLISH; return;
    }
    throw InvalidParamsException(name + " | " + ("Unknown stream::EventType value, received " + std::to_string(val.convert<int64_t>())));
}

template<>
void VarDeserializer::deserialize<stream::EventSelectorType>(const Poco::Dynamic::Var& val, const std::string& name, stream::EventSelectorType& out) {

    switch (val.convert<int64_t>()) {
        case stream::EventSelectorType::CONTEXT_ID:
            out = stream::EventSelectorType::CONTEXT_ID; return;
        case stream::EventSelectorType::STREAMROOM_ID:
            out = stream::EventSelectorType::STREAMROOM_ID; return;
        case stream::EventSelectorType::STREAM_ID:
            out = stream::EventSelectorType::STREAM_ID; return;
    }
    throw InvalidParamsException(name + " | " + ("Unknown stream::EventSelectorType value, received " + std::to_string(val.convert<int64_t>())));
}

template<>
void VarDeserializer::deserialize<stream::SdpWithTypeModel>(const Poco::Dynamic::Var& val, const std::string& name, stream::SdpWithTypeModel& out) {
    TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    deserialize(obj->get("sdp"), name + ".sdp", out.sdp);
    deserialize(obj->get("type"), name + ".type", out.type);
}

template<>
void VarDeserializer::deserialize<stream::StreamTrackInfo>(const Poco::Dynamic::Var& val, const std::string& name, stream::StreamTrackInfo& out) {
    TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    deserialize(obj->get("type"), name + ".type", out.type);
    deserialize(obj->get("mindex"), name + ".mindex", out.mindex);
    deserialize(obj->get("mid"), name + ".mid", out.mid);
    if (obj->has("disabled")) deserialize(obj->get("disabled"), name + ".disabled", out.disabled);
    if (obj->has("codec")) deserialize(obj->get("codec"), name + ".codec", out.codec);
    if (obj->has("description")) deserialize(obj->get("description"), name + ".description", out.description);
    if (obj->has("moderated")) deserialize(obj->get("moderated"), name + ".moderated", out.moderated);
    if (obj->has("simulcast")) deserialize(obj->get("simulcast"), name + ".simulcast", out.simulcast);
    if (obj->has("talking")) deserialize(obj->get("talking"), name + ".talking", out.talking);
}

template<>
void VarDeserializer::deserialize<stream::StreamInfo>(const Poco::Dynamic::Var& val, const std::string& name, stream::StreamInfo& out) {
    TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    deserialize(obj->get("id"), name + ".id", out.id);
    deserialize(obj->get("userId"), name + ".userId", out.userId);
    if (obj->has("metadata")) deserialize(obj->get("metadata"), name + ".metadata", out.metadata);
    if (obj->has("dummy")) deserialize(obj->get("dummy"), name + ".dummy", out.dummy);   // czy to publisher-dummy
    deserialize(obj->get("tracks"), name + ".tracks", out.tracks);
    if (obj->has("talking")) deserialize(obj->get("talking"), name + ".talking", out.talking);
}

template<>
void VarDeserializer::deserialize<stream::NewStreams>(const Poco::Dynamic::Var& val, const std::string& name, stream::NewStreams& out) {
    TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    deserialize(obj->get("room"), name + ".room", out.room);
    deserialize(obj->get("streams"), name + ".streams", out.streams);
}

template<>
void VarDeserializer::deserialize<stream::UpdatedStreamData>(const Poco::Dynamic::Var& val, const std::string& name, stream::UpdatedStreamData& out) {
    TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();

    std::string type;
    deserialize(obj->get("type"), name + ".type", type);
    bool isActive;
    deserialize(obj->get("active"), name + ".active", isActive);
    std::optional<int64_t> streamId;
    if (isActive) deserialize(obj->get("feed_id"), name + ".streamId", streamId);
    std::optional<std::string> streamMid;
    if (isActive) deserialize(obj->get("feed_mid"), name + ".streamMid", streamMid);
    std::optional<std::string> stream_display;
    if (isActive) deserialize(obj->get("feed_display"), name + ".streamDisplay", stream_display);
    std::optional<std::string> codec;
    if (isActive) deserialize(obj->get("codec"), name + ".codec", codec);
    int64_t mindex;
    deserialize(obj->get("mindex"), name + ".mindex", mindex);
    std::string mid;
    deserialize(obj->get("mid"), name + ".mid", mid);
    bool send;
    deserialize(obj->get("send"), name + ".send", send);
    bool ready;
    deserialize(obj->get("ready"), name + ".ready", ready);

    out = {
        .active = isActive,
        .type = type,
        .codec = codec,
        .streamId = streamId,
        .streamMid = streamMid,
        .stream_display = stream_display,
        .mindex = mindex,
        .mid = mid,
        .send = send,
        .ready = ready
    };
}


template<>
void VarDeserializer::deserialize<stream::StreamsUpdatedDataInternal>(const Poco::Dynamic::Var& val, const std::string& name, stream::StreamsUpdatedDataInternal& out) {
    TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    deserialize(obj->get("room"), name + ".room", out.room);
    deserialize(obj->get("streams"), name + ".streams", out.streams);
    if (obj->has("jsep")) deserialize(obj->get("jsep"), name + ".jsep", out.jsep);
}

template<>
void VarDeserializer::deserialize<stream::StreamsUpdatedData>(const Poco::Dynamic::Var& val, const std::string& name, stream::StreamsUpdatedData& out) {
    TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    deserialize(obj->get("room"), name + ".room", out.room);
    deserialize(obj->get("streams"), name + ".streams", out.streams);
}

template<>
void VarDeserializer::deserialize<stream::StreamSubscription>(const Poco::Dynamic::Var& val, const std::string& name, stream::StreamSubscription& out) {
    TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    deserialize(obj->get("streamId"), name + ".streamId", out.streamId);
    if (obj->has("streamTrackId")) deserialize(obj->get("streamTrackId"), name + ".streamTrackId", out.streamTrackId);
}

template<>
void VarDeserializer::deserialize<stream::StreamPublishedEventData>(const Poco::Dynamic::Var& val, const std::string& name, stream::StreamPublishedEventData& out) {
    TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    deserialize(obj->get("streamRoomId"), name + ".streamRoomId", out.streamRoomId);
    deserialize(obj->get("stream"), name + ".stream", out.stream);
    deserialize(obj->get("userId"), name + ".userId", out.userId);
}

template<>
void VarDeserializer::deserialize<stream::StreamUpdatedEventData>(const Poco::Dynamic::Var& val, const std::string& name, stream::StreamUpdatedEventData& out) {
    TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    deserialize(obj->get("streamRoomId"), name + ".streamRoomId", out.streamRoomId);
    deserialize(obj->get("streamsAdded"), name + ".streamsAdded", out.streamsAdded);
    deserialize(obj->get("streamsRemoved"), name + ".streamsRemoved", out.streamsRemoved);
    deserialize(obj->get("streamsModified"), name + ".streamsModified", out.streamsModified);
}

template<>
void VarDeserializer::deserialize<stream::StreamTrackModificationPair>(const Poco::Dynamic::Var& val, const std::string& name, stream::StreamTrackModificationPair& out) {
    TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    if (obj->has("before")) deserialize(obj->get("before"), name + ".before", out.before);
    if (obj->has("after")) deserialize(obj->get("after"), name + ".after", out.after);
}

template<>
void VarDeserializer::deserialize<stream::StreamTrackModification>(const Poco::Dynamic::Var& val, const std::string& name, stream::StreamTrackModification& out) {
    TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    deserialize(obj->get("streamId"), name + ".streamId", out.streamId);
    deserialize(obj->get("tracks"), name + ".tracks", out.tracks);
}