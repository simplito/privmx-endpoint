/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <memory>
#include "privmx/endpoint/stream/StreamVarDeserializer.hpp"
#include "privmx/endpoint/stream/WebRTCInterface.hpp"

#include <Poco/JSON/Array.h>
#include <Poco/JSON/Object.h>

#include "privmx/endpoint/core/TypeValidator.hpp"
#include "privmx/endpoint/core/CoreException.hpp"

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
stream::VideoRoomStreamTrack VarDeserializer::deserialize<stream::VideoRoomStreamTrack>(const Poco::Dynamic::Var& val, const std::string& name) {
    TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    return {
        .type = deserialize<std::string>(obj->get("type"), name + ".type"),
        .codec = deserialize<std::string>(obj->get("codec"), name + ".codec"),
        .mid = deserialize<std::string>(obj->get("mid"), name + ".mid"),
        .mindex = deserialize<int64_t>(obj->get("mindex"), name + ".mindex")
    };
}

template<>
stream::NewPublisherEvent VarDeserializer::deserialize<stream::NewPublisherEvent>(const Poco::Dynamic::Var& val, const std::string& name) {
    TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    return {
        .id = deserialize<int64_t>(obj->get("id"), name + ".id"),
        .video_codec = deserialize<std::string>(obj->get("video_codec"), name + ".video_codec"),
        .streams = deserializeVector<stream::VideoRoomStreamTrack>(obj->get("streams"), name + ".streams")
    };
}

template<>
stream::CurrentPublishersData VarDeserializer::deserialize<stream::CurrentPublishersData>(const Poco::Dynamic::Var& val, const std::string& name) {
    TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    return {
        .room = deserialize<std::string>(obj->get("room"), name + ".room"),
        .publishers = deserializeVector<stream::NewPublisherEvent>(obj->get("publishers"), name + ".publishers")
    };
}

template<>
stream::UpdatedStreamData VarDeserializer::deserialize<stream::UpdatedStreamData>(const Poco::Dynamic::Var& val, const std::string& name) {
    TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    return {
        .type = deserialize<std::string>(obj->get("type"), name + ".type"),
        .streamId = deserialize<int64_t>(obj->get("feed_id"), name + ".streamId"),
        .streamMid = deserialize<int64_t>(obj->get("feed_mid"), name + ".streamMid"),
        .stream_display = deserialize<std::string>(obj->get("feed_display"), name + ".streamDisplay"),
        .mindex = deserialize<int64_t>(obj->get("mindex"), name + ".mindex"),
        .mid = deserialize<std::string>(obj->get("mid"), name + ".mid"),
        .send = deserialize<bool>(obj->get("send"), name + ".send"),
        .ready = deserialize<bool>(obj->get("ready"), name + ".ready")
    };
}


template<>
stream::StreamsUpdatedData VarDeserializer::deserialize<stream::StreamsUpdatedData>(const Poco::Dynamic::Var& val, const std::string& name) {
    TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    std::optional<stream::SdpWithTypeModel> jsep = std::nullopt;
    if (obj->has("jsep")) {
        jsep.emplace(deserialize<stream::SdpWithTypeModel>(obj->get("jsep"), name + ".jsep"));
    }
    return {
        .room = deserialize<std::string>(obj->get("room"), name + ".room"),
        .streams = deserializeVector<stream::UpdatedStreamData>(obj->get("streams"), name + ".streams"),
        .jsep = jsep
    };
}