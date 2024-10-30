#include "privmx/endpoint/core/VarDeserializer.hpp"

#include <Poco/JSON/Array.h>
#include <Poco/JSON/Object.h>

#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/core/TypeValidator.hpp"

using namespace privmx::endpoint::core;

// primitives

template<>
int64_t VarDeserializer::deserialize<int64_t>(const Poco::Dynamic::Var& val, const std::string& name) {
    TypeValidator::validateInteger(val, name);
    return val.convert<Poco::Int64>();
}

template<>
std::string VarDeserializer::deserialize<std::string>(const Poco::Dynamic::Var& val, const std::string& name) {
    TypeValidator::validateString(val, name);
    return val.convert<std::string>();
}

template<>
Buffer VarDeserializer::deserialize<Buffer>(const Poco::Dynamic::Var& val, const std::string& name) {
    TypeValidator::validateBuffer(val, name);
    if (val.type() == typeid(std::string)) {
        return Buffer::from(utils::Base64::toString(val.extract<std::string>()));
    }
    if (val.type() == typeid(Pson::BinaryString)) {
        return Buffer::from(val.extract<Pson::BinaryString>());
    }
    return val.extract<Buffer>();
}

template<>
bool VarDeserializer::deserialize<bool>(const Poco::Dynamic::Var& val, const std::string& name) {
    TypeValidator::validateBoolean(val, name);
    return val.extract<bool>();
}

// // core

template<>
UserWithPubKey VarDeserializer::deserialize<UserWithPubKey>(const Poco::Dynamic::Var& val, const std::string& name) {
    TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    return {.userId = deserialize<std::string>(obj->get("userId"), name + ".userId"),
            .pubKey = deserialize<std::string>(obj->get("pubKey"), name + ".pubKey")};
}

template<>
PagingQuery VarDeserializer::deserialize<PagingQuery>(const Poco::Dynamic::Var& val, const std::string& name) {
    TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    return {.skip = deserialize<int64_t>(obj->get("skip"), name + ".skip"),
            .limit = deserialize<int64_t>(obj->get("limit"), name + ".limit"),
            .sortOrder = deserialize<std::string>(obj->get("sortOrder"), name + ".sortOrder"),
            .lastId = deserializeOptional<std::string>(obj->get("lastId"), name + ".lastId")};
}
