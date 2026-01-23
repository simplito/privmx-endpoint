/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/endpoint/core/CoreException.hpp>
#include "privmx/endpoint/search/VarDeserializer.hpp"

#include <Poco/JSON/Array.h>
#include <Poco/JSON/Object.h>

using namespace privmx::endpoint;
using namespace privmx::endpoint::core;

template<>
search::IndexMode VarDeserializer::deserialize<search::IndexMode>(const Poco::Dynamic::Var& val, const std::string& name) {
    switch (val.convert<int64_t>()) {
        case search::IndexMode::WITH_CONTENT:
            return search::IndexMode::WITH_CONTENT;
        case search::IndexMode::WITHOUT_CONTENT:
            return search::IndexMode::WITHOUT_CONTENT;
    }
    throw InvalidParamsException(name + " | " + ("Unknown search::IndexMode value, received " + std::to_string(val.convert<int64_t>())));
}

template<>
search::Document VarDeserializer::deserialize<search::Document>(const Poco::Dynamic::Var& val, const std::string& name) {
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    return {.documentId = deserialize<int64_t>(obj->get("documentId"), name + ".documentId"),
            .name = deserialize<std::string>(obj->get("name"), name + ".name"),
            .content = deserialize<std::string>(obj->get("content"), name + ".content")};
}
