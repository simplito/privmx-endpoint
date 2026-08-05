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
stream::EventType VarDeserializer::deserialize<stream::EventType>(
    const Poco::Dynamic::Var& val,
    const std::string& name
) {
    switch (val.convert<int64_t>()) {
    case stream::EventType::STREAMROOM_CREATE:
        return stream::EventType::STREAMROOM_CREATE;
    case stream::EventType::STREAMROOM_UPDATE:
        return stream::EventType::STREAMROOM_UPDATE;
    case stream::EventType::STREAMROOM_DELETE:
        return stream::EventType::STREAMROOM_DELETE;
    case stream::EventType::STREAMROOM_JOIN:
        return stream::EventType::STREAMROOM_JOIN;
    case stream::EventType::STREAMROOM_LEAVE:
        return stream::EventType::STREAMROOM_LEAVE;
    case stream::EventType::STREAM_PUBLISH:
        return stream::EventType::STREAM_PUBLISH;
    case stream::EventType::STREAM_UNPUBLISH:
        return stream::EventType::STREAM_UNPUBLISH;
    case stream::EventType::STREAM_SUBSCRIBE:
        return stream::EventType::STREAM_SUBSCRIBE;
    case stream::EventType::STREAM_UNSUBSCRIBE:
        return stream::EventType::STREAM_UNSUBSCRIBE;
    case stream::EventType::STREAM_UPDATE:
        return stream::EventType::STREAM_UPDATE;
    }
    throw InvalidParamsException(
        name + " | " + ("Unknown stream::EventType value, received " + std::to_string(val.convert<int64_t>()))
    );
}

template<>
stream::EventSelectorType VarDeserializer::deserialize<stream::EventSelectorType>(
    const Poco::Dynamic::Var& val,
    const std::string& name
) {

    switch (val.convert<int64_t>()) {
    case stream::EventSelectorType::CONTEXT_ID:
        return stream::EventSelectorType::CONTEXT_ID;
    case stream::EventSelectorType::STREAMROOM_ID:
        return stream::EventSelectorType::STREAMROOM_ID;
    case stream::EventSelectorType::STREAM_ID:
        return stream::EventSelectorType::STREAM_ID;
    }
    throw InvalidParamsException(
        name + " | " + ("Unknown stream::EventSelectorType value, received " + std::to_string(val.convert<int64_t>()))
    );
}

template<>
stream::SdpWithTypeModel VarDeserializer::deserialize<stream::SdpWithTypeModel>(
    const Poco::Dynamic::Var& val,
    const std::string& name
) {
    TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    return {
        .sdp = deserialize<std::string>(obj->get("sdp"), name + ".sdp"),
        .type = deserialize<std::string>(obj->get("type"), name + ".type")
    };
}

template<>
stream::StreamTrackInfo VarDeserializer::deserialize<stream::StreamTrackInfo>(
    const Poco::Dynamic::Var& val,
    const std::string& name
) {
    TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    return {
        .type = deserialize<std::string>(obj->get("type"), name + ".type"),
        .mindex = deserialize<int64_t>(obj->get("mindex"), name + ".mindex"),
        .mid = deserialize<std::string>(obj->get("mid"), name + ".mid"),
        .disabled = deserialize<bool>(obj->get("disabled"), name + ".disabled"),
        .codec =
            {obj->has("codec") ? std::make_optional(deserialize<std::string>(obj->get("codec"), name + ".codec")) :
                                 std::nullopt},
        .description =
            {obj->has("description") ?
                 std::make_optional(deserialize<std::string>(obj->get("description"), name + ".description")) :
                 std::nullopt},
        .moderated = deserialize<bool>(obj->get("moderated"), name + ".moderated"),
        .simulcast = deserialize<bool>(obj->get("simulcast"), name + ".simulcast"),
    };
}

template<>
stream::StreamInfo VarDeserializer::deserialize<stream::StreamInfo>(
    const Poco::Dynamic::Var& val,
    const std::string& name
) {
    TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    return {
        .id = deserialize<int64_t>(obj->get("id"), name + ".id"),
        .userId = deserialize<std::string>(obj->get("userId"), name + ".userId"),
        .metadata =
            {obj->has("metadata") ?
                 std::make_optional(deserialize<std::string>(obj->get("metadata"), name + ".metadata")) :
                 std::nullopt},
        .dummy = deserialize<bool>(obj->get("dummy"), name + ".dummy"),
        .tracks = deserializeVector<stream::StreamTrackInfo>(obj->get("tracks"), name + ".tracks"),
    };
}

template<>
stream::StreamSubscription VarDeserializer::deserialize<stream::StreamSubscription>(
    const Poco::Dynamic::Var& val,
    const std::string& name
) {
    TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    std::optional<std::string> trackId{
        obj->has("streamTrackId") ?
            std::make_optional(deserialize<std::string>(obj->get("streamTrackId"), name + ".streamTrackId")) :
            std::nullopt
    };
    return {.streamId = deserialize<int64_t>(obj->get("streamId"), name + ".streamId"), .streamTrackId = trackId};
}

template<>
stream::StreamPublishedEventData VarDeserializer::deserialize<stream::StreamPublishedEventData>(
    const Poco::Dynamic::Var& val,
    const std::string& name
) {
    TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    return {
        .streamRoomId = deserialize<std::string>(obj->get("streamRoomId"), name + ".streamRoomId"),
        .stream = deserialize<stream::StreamInfo>(obj->get("stream"), name + ".stream"),
        .userId = deserialize<std::string>(obj->get("userId"), name + ".userId"),
    };
}

template<>
stream::StreamUpdatedEventData VarDeserializer::deserialize<stream::StreamUpdatedEventData>(
    const Poco::Dynamic::Var& val,
    const std::string& name
) {
    TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();

    return {
        .streamRoomId = deserialize<std::string>(obj->get("streamRoomId"), name + ".streamRoomId"),
        .streamId = deserialize<int64_t>(obj->get("streamId"), name + ".streamId"),
        .userId = deserialize<std::string>(obj->get("userId"), name + ".userId"),
        .tracksAdded = deserializeVector<stream::StreamTrackInfo>(obj->get("tracksAdded"), name + ".tracksAdded"),
        .tracksRemoved = deserializeVector<stream::StreamTrackInfo>(obj->get("tracksRemoved"), name + ".tracksRemoved"),
        .tracksModified = deserializeVector<stream::StreamTrackModificationPair>(
            obj->get("tracksModified"), name + ".tracksModified"
        )
    };
}

template<>
stream::StreamTrackModificationPair VarDeserializer::deserialize<stream::StreamTrackModificationPair>(
    const Poco::Dynamic::Var& val,
    const std::string& name
) {
    TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();

    return {
        .before = obj->has("before") ?
            std::make_optional(deserialize<stream::StreamTrackInfo>(obj->get("before"), name + ".before")) :
            std::nullopt,
        .after = obj->has("after") ?
            std::make_optional(deserialize<stream::StreamTrackInfo>(obj->get("after"), name + ".after")) :
            std::nullopt,
    };
}

template<>
stream::DataChannelMessage VarDeserializer::deserialize<stream::DataChannelMessage>(
    const Poco::Dynamic::Var& val,
    const std::string& name
) {
    TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    return {
        .data = deserialize<core::Buffer>(obj->get("data"), name + ".data"),
        .seq = deserialize<int64_t>(obj->get("seq"), name + ".seq"),
    };
}
