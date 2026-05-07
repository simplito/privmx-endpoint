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
void VarDeserializer::deserialize<thread::EventType>(const Poco::Dynamic::Var& val, const std::string& name, thread::EventType& out) {
    switch (val.convert<int64_t>()) {
        case thread::EventType::THREAD_CREATE:
            out = thread::EventType::THREAD_CREATE; return;
        case thread::EventType::THREAD_UPDATE:
            out = thread::EventType::THREAD_UPDATE; return;
        case thread::EventType::THREAD_DELETE:
            out = thread::EventType::THREAD_DELETE; return;
        case thread::EventType::THREAD_STATS:
            out = thread::EventType::THREAD_STATS; return;
        case thread::EventType::MESSAGE_CREATE:
            out = thread::EventType::MESSAGE_CREATE; return;
        case thread::EventType::MESSAGE_UPDATE:
            out = thread::EventType::MESSAGE_UPDATE; return;
        case thread::EventType::MESSAGE_DELETE:
            out = thread::EventType::MESSAGE_DELETE; return;
        case thread::EventType::COLLECTION_CHANGE:
            out = thread::EventType::COLLECTION_CHANGE; return;
    }
    throw InvalidParamsException(name + " | " + ("Unknown thread::EventType value, received " + std::to_string(val.convert<int64_t>())));
}

template<>
void VarDeserializer::deserialize<thread::EventSelectorType>(const Poco::Dynamic::Var& val, const std::string& name, thread::EventSelectorType& out) {

    switch (val.convert<int64_t>()) {
        case thread::EventSelectorType::CONTEXT_ID:
            out = thread::EventSelectorType::CONTEXT_ID; return;
        case thread::EventSelectorType::THREAD_ID:
            out = thread::EventSelectorType::THREAD_ID; return;
        case thread::EventSelectorType::MESSAGE_ID:
            out = thread::EventSelectorType::MESSAGE_ID; return;
    }
    throw InvalidParamsException(name + " | " + ("Unknown thread::EventSelectorType value, received " + std::to_string(val.convert<int64_t>())));
}