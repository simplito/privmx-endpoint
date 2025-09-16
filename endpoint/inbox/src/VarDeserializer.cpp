/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/inbox/VarDeserializer.hpp"

#include <Poco/JSON/Array.h>
#include <Poco/JSON/Object.h>

#include <privmx/endpoint/core/CoreException.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::core;

template<>
inbox::FilesConfig VarDeserializer::deserialize<inbox::FilesConfig>(const Poco::Dynamic::Var& val,
                                                                    const std::string& name) {
    core::TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    return {.minCount = deserialize<int64_t>(obj->get("minCount"), name + ".minCount"),
            .maxCount = deserialize<int64_t>(obj->get("maxCount"), name + ".maxCount"),
            .maxFileSize = deserialize<int64_t>(obj->get("maxFileSize"), name + ".maxFileSize"),
            .maxWholeUploadSize = deserialize<int64_t>(obj->get("maxWholeUploadSize"), name + ".maxWholeUploadSize")};
}

template<>
inbox::EventType VarDeserializer::deserialize<inbox::EventType>(const Poco::Dynamic::Var& val, const std::string& name) {

    switch (val.convert<int64_t>()) {
        case inbox::EventType::INBOX_CREATE:
            return inbox::EventType::INBOX_CREATE;
        case inbox::EventType::INBOX_UPDATE:
            return inbox::EventType::INBOX_UPDATE;
        case inbox::EventType::INBOX_DELETE:
            return inbox::EventType::INBOX_DELETE;
        case inbox::EventType::ENTRY_CREATE:
            return inbox::EventType::ENTRY_CREATE;
        case inbox::EventType::ENTRY_DELETE:
            return inbox::EventType::ENTRY_DELETE;
        case inbox::EventType::COLLECTION_CHANGE:
            return inbox::EventType::COLLECTION_CHANGE;
    }
    throw InvalidParamsException(name + " | " + ("Unknown inbox::EventType value, received " + std::to_string(val.convert<int64_t>())));
}

template<>
inbox::EventSelectorType VarDeserializer::deserialize<inbox::EventSelectorType>(const Poco::Dynamic::Var& val, const std::string& name) {

    switch (val.convert<int64_t>()) {
        case inbox::EventSelectorType::CONTEXT_ID:
            return inbox::EventSelectorType::CONTEXT_ID;
        case inbox::EventSelectorType::INBOX_ID:
            return inbox::EventSelectorType::INBOX_ID;
        case inbox::EventSelectorType::ENTRY_ID:
            return inbox::EventSelectorType::ENTRY_ID;
    }
    throw InvalidParamsException(name + " | " + ("Unknown inbox::EventSelectorType value, received " + std::to_string(val.convert<int64_t>())));
}