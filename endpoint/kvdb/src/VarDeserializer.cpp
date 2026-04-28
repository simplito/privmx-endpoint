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
void VarDeserializer::deserialize<kvdb::EventType>(const Poco::Dynamic::Var& val, const std::string& name, kvdb::EventType& out) {

    switch (val.convert<int64_t>()) {
        case kvdb::EventType::KVDB_CREATE:
            out = kvdb::EventType::KVDB_CREATE; return;
        case kvdb::EventType::KVDB_UPDATE:
            out = kvdb::EventType::KVDB_UPDATE; return;
        case kvdb::EventType::KVDB_DELETE:
            out = kvdb::EventType::KVDB_DELETE; return;
        case kvdb::EventType::KVDB_STATS:
            out = kvdb::EventType::KVDB_STATS; return;
        case kvdb::EventType::ENTRY_CREATE:
            out = kvdb::EventType::ENTRY_CREATE; return;
        case kvdb::EventType::ENTRY_UPDATE:
            out = kvdb::EventType::ENTRY_UPDATE; return;
        case kvdb::EventType::ENTRY_DELETE:
            out = kvdb::EventType::ENTRY_DELETE; return;
        case kvdb::EventType::COLLECTION_CHANGE:
            out = kvdb::EventType::COLLECTION_CHANGE; return;
    }
    throw InvalidParamsException(name + " | " + ("Unknown kvdb::EventType value, received " + std::to_string(val.convert<int64_t>())));
}

template<>
void VarDeserializer::deserialize<kvdb::EventSelectorType>(const Poco::Dynamic::Var& val, const std::string& name, kvdb::EventSelectorType& out) {

    switch (val.convert<int64_t>()) {
        case kvdb::EventSelectorType::CONTEXT_ID:
            out = kvdb::EventSelectorType::CONTEXT_ID; return;
        case kvdb::EventSelectorType::KVDB_ID:
            out = kvdb::EventSelectorType::KVDB_ID; return;
    }
    throw InvalidParamsException(name + " | " + ("Unknown kvdb::EventSelectorType value, received " + std::to_string(val.convert<int64_t>())));
}