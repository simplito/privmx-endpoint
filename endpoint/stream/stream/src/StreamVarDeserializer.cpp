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
