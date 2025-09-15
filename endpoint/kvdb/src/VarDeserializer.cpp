/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/kvdb/VarDeserializer.hpp"

#include <Poco/JSON/Array.h>
#include <Poco/JSON/Object.h>

#include <privmx/endpoint/core/CoreException.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::core;

template<>
kvdb::EventType VarDeserializer::deserialize<kvdb::EventType>(const Poco::Dynamic::Var& val, const std::string& name) {

    switch (val.convert<int64_t>()) {
        case kvdb::EventType::KVDB_CREATE:
            return kvdb::EventType::KVDB_CREATE;
        case kvdb::EventType::KVDB_UPDATE:
            return kvdb::EventType::KVDB_UPDATE;
        case kvdb::EventType::KVDB_DELETE:
            return kvdb::EventType::KVDB_DELETE;
        case kvdb::EventType::KVDB_STATS:
            return kvdb::EventType::KVDB_STATS;
        case kvdb::EventType::ENTRY_CREATE:
            return kvdb::EventType::ENTRY_CREATE;
        case kvdb::EventType::ENTRY_UPDATE:
            return kvdb::EventType::ENTRY_UPDATE;
        case kvdb::EventType::ENTRY_DELETE:
            return kvdb::EventType::ENTRY_DELETE;
        case kvdb::EventType::COLLECTION_CHANGE:
            return kvdb::EventType::COLLECTION_CHANGE;
    }
    throw InvalidParamsException(name + " | " + ("Unknown kvdb::EventType value, received " + std::to_string(val.convert<int64_t>())));
}

template<>
kvdb::EventSelectorType VarDeserializer::deserialize<kvdb::EventSelectorType>(const Poco::Dynamic::Var& val, const std::string& name) {

    switch (val.convert<int64_t>()) {
        case kvdb::EventSelectorType::CONTEXT_ID:
            return kvdb::EventSelectorType::CONTEXT_ID;
        case kvdb::EventSelectorType::KVDB_ID:
            return kvdb::EventSelectorType::KVDB_ID;
    }
    throw InvalidParamsException(name + " | " + ("Unknown kvdb::EventSelectorType value, received " + std::to_string(val.convert<int64_t>())));
}