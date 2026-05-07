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
void VarDeserializer::deserialize<store::EventType>(const Poco::Dynamic::Var& val, const std::string& name, store::EventType& out) {

    switch (val.convert<int64_t>()) {
        case store::EventType::STORE_CREATE:
            out = store::EventType::STORE_CREATE; return;
        case store::EventType::STORE_UPDATE:
            out = store::EventType::STORE_UPDATE; return;
        case store::EventType::STORE_DELETE:
            out = store::EventType::STORE_DELETE; return;
        case store::EventType::STORE_STATS:
            out = store::EventType::STORE_STATS; return;
        case store::EventType::FILE_CREATE:
            out = store::EventType::FILE_CREATE; return;
        case store::EventType::FILE_UPDATE:
            out = store::EventType::FILE_UPDATE; return;
        case store::EventType::FILE_DELETE:
            out = store::EventType::FILE_DELETE; return;
        case store::EventType::COLLECTION_CHANGE:
            out = store::EventType::COLLECTION_CHANGE; return;
    }
    throw InvalidParamsException(name + " | " + ("Unknown store::EventType value, received " + std::to_string(val.convert<int64_t>())));
}

template<>
void VarDeserializer::deserialize<store::EventSelectorType>(const Poco::Dynamic::Var& val, const std::string& name, store::EventSelectorType& out) {

    switch (val.convert<int64_t>()) {
        case store::EventSelectorType::CONTEXT_ID:
            out = store::EventSelectorType::CONTEXT_ID; return;
        case store::EventSelectorType::STORE_ID:
            out = store::EventSelectorType::STORE_ID; return;
        case store::EventSelectorType::FILE_ID:
            out = store::EventSelectorType::FILE_ID; return;
    }
    throw InvalidParamsException(name + " | " + ("Unknown store::EventSelectorType value, received " + std::to_string(val.convert<int64_t>())));
}