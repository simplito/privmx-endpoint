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
stream::Settings VarDeserializer::deserialize<stream::Settings>(const Poco::Dynamic::Var& val, const std::string& name) {
    core::TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    // empty object - for future use
    return {};
}

template<>
stream::EventType VarDeserializer::deserialize<stream::EventType>(const Poco::Dynamic::Var& val, const std::string& name) {
    switch (val.convert<int64_t>()) {
        case stream::EventType::STREAMROOM_CREATE:
            return stream::EventType::STREAMROOM_CREATE;
        case stream::EventType::STREAMROOM_UPDATE:
            return stream::EventType::STREAMROOM_UPDATE;
        case stream::EventType::STREAMROOM_DELETE:
            return stream::EventType::STREAMROOM_DELETE;
        case stream::EventType::STREAM_JOIN:
            return stream::EventType::STREAM_JOIN;
        case stream::EventType::STREAM_LEAVE:
            return stream::EventType::STREAM_LEAVE;
        case stream::EventType::STREAM_PUBLISH:
            return stream::EventType::STREAM_PUBLISH;
        case stream::EventType::STREAM_UNPUBLISH:
            return stream::EventType::STREAM_UNPUBLISH;
    }
    throw InvalidParamsException(name + " | " + ("Unknown stream::EventType value, received " + std::to_string(val.convert<int64_t>())));
}

template<>
stream::EventSelectorType VarDeserializer::deserialize<stream::EventSelectorType>(const Poco::Dynamic::Var& val, const std::string& name) {

    switch (val.convert<int64_t>()) {
        case stream::EventSelectorType::CONTEXT_ID:
            return stream::EventSelectorType::CONTEXT_ID;
        case stream::EventSelectorType::STREAMROOM_ID:
            return stream::EventSelectorType::STREAMROOM_ID;
        case stream::EventSelectorType::STREAM_ID:
            return stream::EventSelectorType::STREAM_ID;
    }
    throw InvalidParamsException(name + " | " + ("Unknown stream::EventSelectorType value, received " + std::to_string(val.convert<int64_t>())));
}

template<>
stream::SdpWithTypeModel VarDeserializer::deserialize<stream::SdpWithTypeModel>(const Poco::Dynamic::Var& val, const std::string& name) {
    TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    return {
        .sdp = deserialize<std::string>(obj->get("sdp"), name + ".sdp"),
        .type = deserialize<std::string>(obj->get("type"), name + ".type")
    };
}

template<>
stream::UpdateSessionIdModel VarDeserializer::deserialize<stream::UpdateSessionIdModel>(const Poco::Dynamic::Var& val, const std::string& name) {
    TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    return {
        .streamRoomId = deserialize<std::string>(obj->get("streamRoomId"), name + ".streamRoomId"),
        .connectionType = deserialize<std::string>(obj->get("connectionType"), name + ".connectionType"),
        .sessionId = deserialize<int64_t>(obj->get("sessionId"), name + ".sessionId")
    };
}

template<>
stream::StreamTrackInfo VarDeserializer::deserialize<stream::StreamTrackInfo>(const Poco::Dynamic::Var& val, const std::string& name) {
    TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    return {
        .type = deserialize<std::string>(obj->get("type"), name + ".type"),
        .mindex = deserialize<int64_t>(obj->get("mindex"), name + ".mindex"),
        .mid = deserialize<std::string>(obj->get("mid"), name + ".mid"),
        .disabled = {obj->has("disabled") ? std::make_optional(deserialize<bool>(obj->get("disabled"), name + ".disabled")) : std::nullopt},
        .codec = {obj->has("codec") ? std::make_optional(deserialize<std::string>(obj->get("codec"), name + ".codec")) : std::nullopt},
        .description = {obj->has("description") ? std::make_optional(deserialize<std::string>(obj->get("description"), name + ".description")) : std::nullopt},
        .moderated = {obj->has("moderated") ? std::make_optional(deserialize<bool>(obj->get("moderated"), name + ".moderated")) : std::nullopt},
        .simulcast = {obj->has("simulcast") ? std::make_optional(deserialize<bool>(obj->get("simulcast"), name + ".simulcast")) : std::nullopt},
        .talking = {obj->has("talking") ? std::make_optional(deserialize<bool>(obj->get("talking"), name + ".talking")) : std::nullopt},
    };
}

template<>
stream::StreamInfo VarDeserializer::deserialize<stream::StreamInfo>(const Poco::Dynamic::Var& val, const std::string& name) {
    TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    return {
        .id = deserialize<int64_t>(obj->get("id"), name + ".id"),
        .userId = deserialize<std::string>(obj->get("userId"), name + ".userId"),
        .metadata = {obj->has("metadata") ? std::make_optional(deserialize<std::string>(obj->get("metadata"), name + ".metadata")) : std::nullopt},
        .dummy = {obj->has("dummy") ? std::make_optional(deserialize<bool>(obj->get("dummy"), name + ".dummy")) : std::nullopt},             // czy to publisher-dummy
        .tracks = deserializeVector<stream::StreamTrackInfo>(obj->get("tracks"), name + ".tracks"),
        .talking = {obj->has("talking") ? std::make_optional(deserialize<bool>(obj->get("talking"), name + ".talking")) : std::nullopt},
    };
}

template<>
stream::NewStreams VarDeserializer::deserialize<stream::NewStreams>(const Poco::Dynamic::Var& val, const std::string& name) {
    TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    return {
        .room = deserialize<std::string>(obj->get("room"), name + ".room"),
        .streams = deserializeVector<stream::StreamInfo>(obj->get("streams"), name + ".streams")
    };
}

template<>
stream::UpdatedStreamData VarDeserializer::deserialize<stream::UpdatedStreamData>(const Poco::Dynamic::Var& val, const std::string& name) {
    TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();

    auto type = deserialize<std::string>(obj->get("type"), name + ".type");
    bool isActive = deserialize<bool>(obj->get("active"), name + ".active");
    std::optional<int64_t> streamId {isActive ? std::make_optional(deserialize<int64_t>(obj->get("feed_id"), name + ".streamId")) : std::nullopt};
    std::optional<std::string> streamMid {isActive ? std::make_optional(deserialize<std::string>(obj->get("feed_mid"), name + ".streamMid")) : std::nullopt};
    std::optional<std::string> stream_display {isActive ? std::make_optional(deserialize<std::string>(obj->get("feed_display"), name + ".streamDisplay")) : std::nullopt};
    std::optional<std::string> codec {isActive ? std::make_optional(deserialize<std::string>(obj->get("codec"), name + ".codec")) : std::nullopt};
    auto mindex = deserialize<int64_t>(obj->get("mindex"), name + ".mindex");
    auto mid = deserialize<std::string>(obj->get("mid"), name + ".mid");
    auto send = deserialize<bool>(obj->get("send"), name + ".send");
    auto ready = deserialize<bool>(obj->get("ready"), name + ".ready");

    return {
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
stream::StreamsUpdatedDataInternal VarDeserializer::deserialize<stream::StreamsUpdatedDataInternal>(const Poco::Dynamic::Var& val, const std::string& name) {
    TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    std::optional<stream::SdpWithTypeModel> jsep = std::nullopt;
    if (obj->has("jsep")) {
        jsep.emplace(deserialize<stream::SdpWithTypeModel>(obj->get("jsep"), name + ".jsep"));
    }
    auto room = deserialize<std::string>(obj->get("room"), name + ".room");
    auto streams = deserializeVector<stream::UpdatedStreamData>(obj->get("streams"), name + ".streams");
    return {
        .room = deserialize<std::string>(obj->get("room"), name + ".room"),
        .streams = deserializeVector<stream::UpdatedStreamData>(obj->get("streams"), name + ".streams"),
        .jsep = jsep
    };
}

template<>
stream::StreamsUpdatedData VarDeserializer::deserialize<stream::StreamsUpdatedData>(const Poco::Dynamic::Var& val, const std::string& name) {
    TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();

    return {
        .room = deserialize<std::string>(obj->get("room"), name + ".room"),
        .streams = deserializeVector<stream::UpdatedStreamData>(obj->get("streams"), name + ".streams")
    };
}

template<>
stream::StreamSubscription VarDeserializer::deserialize<stream::StreamSubscription>(const Poco::Dynamic::Var& val, const std::string& name) {
    TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    std::optional<std::string> trackId {obj->has("streamTrackId") ? std::make_optional(deserialize<std::string>(obj->get("streamTrackId"), name + ".streamTrackId")) : std::nullopt};
    return {
        .streamId = deserialize<int64_t>(obj->get("streamId"), name + ".streamId"),
        .streamTrackId = trackId
    };
}

template<>
stream::StreamPublishedEventData VarDeserializer::deserialize<stream::StreamPublishedEventData>(const Poco::Dynamic::Var& val, const std::string& name) {
    TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    return {
        .streamRoomId = deserialize<std::string>(obj->get("streamRoomId"), name + ".streamRoomId"),
        .stream = deserialize<stream::StreamInfo>(obj->get("stream"), name + ".stream"),
        .userId = deserialize<std::string>(obj->get("userId"), name + ".userId"),
    };
}

template<>
stream::StreamUpdatedEventData VarDeserializer::deserialize<stream::StreamUpdatedEventData>(const Poco::Dynamic::Var& val, const std::string& name) {
    TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();

    return {
        .streamRoomId = deserialize<std::string>(obj->get("streamRoomId"), name + ".streamRoomId"),
        .streamId = deserialize<int64_t>(obj->get("streamId"), name + ".streamId"),
        .userId = deserialize<std::string>(obj->get("userId"), name + ".userId"),
        .streamsAdded = deserializeVector<stream::StreamInfo>(obj->get("streamsAdded"), name + ".streamsAdded"),
        .streamsRemoved = deserializeVector<stream::StreamInfo>(obj->get("streamsRemoved"), name + ".streamsRemoved"),
        .streamsModified = deserializeVector<stream::StreamTrackModification>(obj->get("streamsModified"), name + ".streamsModified")
    };
}

template<>
stream::StreamTrackModificationPair VarDeserializer::deserialize<stream::StreamTrackModificationPair>(const Poco::Dynamic::Var& val, const std::string& name) {
    TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();

    return {
        .before = obj->has("before") ? std::make_optional(deserialize<stream::StreamTrackInfo>(obj->get("before"), name + ".before")) : std::nullopt,
        .after = obj->has("after") ? std::make_optional(deserialize<stream::StreamTrackInfo>(obj->get("after"), name + ".after")) : std::nullopt,
    };
}

template<>
stream::StreamTrackModification VarDeserializer::deserialize<stream::StreamTrackModification>(const Poco::Dynamic::Var& val, const std::string& name) {
    TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();

    return {
        .streamId = deserialize<int64_t>(obj->get("streamId"), name + ".streamId"),
        .tracks = deserializeVector<stream::StreamTrackModificationPair>(obj->get("tracks"), name + ".tracks")
    };
}