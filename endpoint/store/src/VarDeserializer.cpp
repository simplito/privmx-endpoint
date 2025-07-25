/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/store/VarDeserializer.hpp"

#include <Poco/JSON/Array.h>
#include <Poco/JSON/Object.h>

#include <privmx/endpoint/core/CoreException.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::core;

template<>
store::EventType VarDeserializer::deserialize<store::EventType>(const Poco::Dynamic::Var& val, const std::string& name) {

    switch (val.convert<int64_t>()) {
        case store::EventType::STORE_CREATE:
            return store::EventType::STORE_CREATE;
        case store::EventType::STORE_UPDATE:
            return store::EventType::STORE_UPDATE;
        case store::EventType::STORE_DELETE:
            return store::EventType::STORE_DELETE;
        case store::EventType::STORE_STATS:
            return store::EventType::STORE_STATS;
        case store::EventType::FILE_CREATE:
            return store::EventType::FILE_CREATE;
        case store::EventType::FILE_UPDATE:
            return store::EventType::FILE_UPDATE;
        case store::EventType::FILE_DELETE:
            return store::EventType::FILE_DELETE;
    }
    throw InvalidParamsException("Unknown store::EventType value");
}

template<>
store::EventSelectorType VarDeserializer::deserialize<store::EventSelectorType>(const Poco::Dynamic::Var& val, const std::string& name) {

    switch (val.convert<int64_t>()) {
        case store::EventSelectorType::CONTEXT_ID:
            return store::EventSelectorType::CONTEXT_ID;
        case store::EventSelectorType::STORE_ID:
            return store::EventSelectorType::STORE_ID;
        case store::EventSelectorType::FILE_ID:
            return store::EventSelectorType::FILE_ID;
    }
    throw InvalidParamsException("Unknown store::EventSelectorType value");
}