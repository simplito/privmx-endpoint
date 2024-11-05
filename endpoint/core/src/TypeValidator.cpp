/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/core/TypeValidator.hpp"

#include <Poco/JSON/Array.h>
#include <Poco/JSON/Object.h>

#include <Pson/BinaryString.hpp>

#include "privmx/endpoint/core/Buffer.hpp"
#include "privmx/endpoint/core/CoreException.hpp"

using namespace privmx::endpoint::core;

void TypeValidator::validateInteger(const Poco::Dynamic::Var& val, const std::string& name) {
    validateNotEmpty(val, name, "integer");
    if (!val.isInteger()) {
        throw InvalidArgumentTypeException(name + " | Expected integer, value has type " + val.type().name());
    }
}

void TypeValidator::validateString(const Poco::Dynamic::Var& val, const std::string& name) {
    validateNotEmpty(val, name, "string");
    if (!val.isString()) {
        throw InvalidArgumentTypeException(name + " | Expected string, value has type " + val.type().name());
    }
}

void TypeValidator::validateBuffer(const Poco::Dynamic::Var& val, const std::string& name) {
    validateNotEmpty(val, name, "buffer");
    if (!val.isString() && val.type() != typeid(Pson::BinaryString) && val.type() != typeid(Buffer)) {
        throw InvalidArgumentTypeException(name + " | Expected buffer, value has type " + val.type().name());
    }
}

void TypeValidator::validateBoolean(const Poco::Dynamic::Var& val, const std::string& name) {
    validateNotEmpty(val, name, "boolean");
    if (!val.isBoolean()) {
        throw InvalidArgumentTypeException(name + " | Expected boolean, value has type " + val.type().name());
    }
}

void TypeValidator::validateArray(const Poco::Dynamic::Var& val, const std::string& name) {
    validateNotEmpty(val, name, "array");
    if (val.type() != typeid(Poco::JSON::Array::Ptr)) {
        throw InvalidArgumentTypeException(name + " | Expected array, value has type " + val.type().name());
    }
}

void TypeValidator::validateObject(const Poco::Dynamic::Var& val, const std::string& name) {
    validateNotEmpty(val, name, "object");
    if (val.type() != typeid(Poco::JSON::Object::Ptr)) {
        throw InvalidArgumentTypeException(name + " | Expected object, value has type " + val.type().name());
    }
}

void TypeValidator::validateNotEmpty(const Poco::Dynamic::Var& val, const std::string& name,
                                     const std::string& expected) {
    if (val.isEmpty()) {
        throw InvalidArgumentTypeException(name + " | Expected " + expected + ", value is empty");
    }
}
