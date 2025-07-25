/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/thread/VarDeserializer.hpp"

#include <Poco/JSON/Array.h>
#include <Poco/JSON/Object.h>

#include <privmx/endpoint/core/CoreException.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::core;

template<>
thread::EventType VarDeserializer::deserialize<thread::EventType>(const Poco::Dynamic::Var& val, const std::string& name) {

    switch (val.convert<int64_t>()) {
        case thread::EventType::THREAD_CREATE:
            return thread::EventType::THREAD_CREATE;
        case thread::EventType::THREAD_UPDATE:
            return thread::EventType::THREAD_UPDATE;
        case thread::EventType::THREAD_DELETE:
            return thread::EventType::THREAD_DELETE;
        case thread::EventType::THREAD_STATS:
            return thread::EventType::THREAD_STATS;
        case thread::EventType::MESSAGE_CREATE:
            return thread::EventType::MESSAGE_CREATE;
        case thread::EventType::MESSAGE_UPDATE:
            return thread::EventType::MESSAGE_UPDATE;
        case thread::EventType::MESSAGE_DELETE:
            return thread::EventType::MESSAGE_DELETE;
    }
    throw InvalidParamsException("Unknown thread::EventType value");
}

template<>
thread::EventSelectorType VarDeserializer::deserialize<thread::EventSelectorType>(const Poco::Dynamic::Var& val, const std::string& name) {

    switch (val.convert<int64_t>()) {
        case thread::EventSelectorType::CONTEXT_ID:
            return thread::EventSelectorType::CONTEXT_ID;
        case thread::EventSelectorType::THREAD_ID:
            return thread::EventSelectorType::THREAD_ID;
        case thread::EventSelectorType::MESSAGE_ID:
            return thread::EventSelectorType::MESSAGE_ID;
    }
    throw InvalidParamsException("Unknown thread::EventSelectorType value");
}