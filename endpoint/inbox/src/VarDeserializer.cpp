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
void VarDeserializer::deserialize<inbox::FilesConfig>(const Poco::Dynamic::Var& val,
                                                      const std::string& name,
                                                      inbox::FilesConfig& out) {
    core::TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    deserialize(obj->get("minCount"), name + ".minCount", out.minCount);
    deserialize(obj->get("maxCount"), name + ".maxCount", out.maxCount);
    deserialize(obj->get("maxFileSize"), name + ".maxFileSize", out.maxFileSize);
    deserialize(obj->get("maxWholeUploadSize"), name + ".maxWholeUploadSize", out.maxWholeUploadSize);
}

template<>
void VarDeserializer::deserialize<inbox::EventType>(const Poco::Dynamic::Var& val, const std::string& name, inbox::EventType& out) {

    switch (val.convert<int64_t>()) {
        case inbox::EventType::INBOX_CREATE:
            out = inbox::EventType::INBOX_CREATE; return;
        case inbox::EventType::INBOX_UPDATE:
            out = inbox::EventType::INBOX_UPDATE; return;
        case inbox::EventType::INBOX_DELETE:
            out = inbox::EventType::INBOX_DELETE; return;
        case inbox::EventType::ENTRY_CREATE:
            out = inbox::EventType::ENTRY_CREATE; return;
        case inbox::EventType::ENTRY_DELETE:
            out = inbox::EventType::ENTRY_DELETE; return;
        case inbox::EventType::COLLECTION_CHANGE:
            out = inbox::EventType::COLLECTION_CHANGE; return;
    }
    throw InvalidParamsException(name + " | " + ("Unknown inbox::EventType value, received " + std::to_string(val.convert<int64_t>())));
}

template<>
void VarDeserializer::deserialize<inbox::EventSelectorType>(const Poco::Dynamic::Var& val, const std::string& name, inbox::EventSelectorType& out) {

    switch (val.convert<int64_t>()) {
        case inbox::EventSelectorType::CONTEXT_ID:
            out = inbox::EventSelectorType::CONTEXT_ID; return;
        case inbox::EventSelectorType::INBOX_ID:
            out = inbox::EventSelectorType::INBOX_ID; return;
        case inbox::EventSelectorType::ENTRY_ID:
            out = inbox::EventSelectorType::ENTRY_ID; return;
    }
    throw InvalidParamsException(name + " | " + ("Unknown inbox::EventSelectorType value, received " + std::to_string(val.convert<int64_t>())));
}