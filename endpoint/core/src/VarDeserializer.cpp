/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/core/VarDeserializer.hpp"

#include <Poco/JSON/Array.h>
#include <Poco/JSON/Object.h>

#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/core/TypeValidator.hpp"

using namespace privmx::endpoint::core;

// primitives

template<>
void VarDeserializer::deserialize<int64_t>(const Poco::Dynamic::Var& val, const std::string& name, int64_t& out) {
    TypeValidator::validateInteger(val, name);
    out = val.convert<Poco::Int64>();
}

template<>
void VarDeserializer::deserialize<std::string>(const Poco::Dynamic::Var& val, const std::string& name, std::string& out) {
    TypeValidator::validateString(val, name);
    out = val.convert<std::string>();
}

template<>
void VarDeserializer::deserialize<Buffer>(const Poco::Dynamic::Var& val, const std::string& name, Buffer& out) {
    TypeValidator::validateBuffer(val, name);
    if (val.type() == typeid(std::string)) {
        out = Buffer::from(utils::Base64::toString(val.extract<std::string>()));
        return;
    }
    if (val.type() == typeid(Pson::BinaryString)) {
        out = Buffer::from(val.extract<Pson::BinaryString>());
        return;
    }
    out = val.extract<Buffer>();
}

template<>
void VarDeserializer::deserialize<bool>(const Poco::Dynamic::Var& val, const std::string& name, bool& out) {
    TypeValidator::validateBoolean(val, name);
    out = val.extract<bool>();
}

template<>
void VarDeserializer::deserialize<Poco::JSON::Object::Ptr>(const Poco::Dynamic::Var& val, const std::string& name, Poco::JSON::Object::Ptr& out) {
    TypeValidator::validateObject(val, name);
    out = val.extract<Poco::JSON::Object::Ptr>();
}

