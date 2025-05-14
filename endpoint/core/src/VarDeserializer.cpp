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

template<>
Poco::JSON::Object::Ptr VarDeserializer::deserialize<Poco::JSON::Object::Ptr>(const Poco::Dynamic::Var& val, const std::string& name) {
    TypeValidator::validateObject(val, name);
    return val.extract<Poco::JSON::Object::Ptr>();
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
    std::optional<std::string> query;
    auto tmp = deserializeOptional<Poco::JSON::Object::Ptr>(obj->get("query"), name + ".query");
    if(tmp.has_value()) {
        query = privmx::utils::Utils::stringify(tmp.value());
    }
    return {.skip = deserialize<int64_t>(obj->get("skip"), name + ".skip"),
            .limit = deserialize<int64_t>(obj->get("limit"), name + ".limit"),
            .sortOrder = deserialize<std::string>(obj->get("sortOrder"), name + ".sortOrder"),
            .lastId = deserializeOptional<std::string>(obj->get("lastId"), name + ".lastId"),
            .queryAsJson = deserializeOptional<std::string>(obj->get("queryAsJson"), name + ".queryAsJson")
    };
}


template<>
ContainerPolicyWithoutItem VarDeserializer::deserialize<ContainerPolicyWithoutItem>(const Poco::Dynamic::Var& val, const std::string& name) {
    TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    return {
        .get = deserializeOptional<std::string>(obj->get("get"), name + ".get"),
        .update = deserializeOptional<std::string>(obj->get("update"), name + ".update"),
        .delete_ = deserializeOptional<std::string>(obj->get("delete_"), name + ".delete_"),
        .updatePolicy = deserializeOptional<std::string>(obj->get("updatePolicy"), name + ".updatePolicy"),
        .updaterCanBeRemovedFromManagers = deserializeOptional<std::string>(obj->get("updaterCanBeRemovedFromManagers"), name + ".updaterCanBeRemovedFromManagers"),
        .ownerCanBeRemovedFromManagers = deserializeOptional<std::string>(obj->get("ownerCanBeRemovedFromManagers"), name + ".ownerCanBeRemovedFromManagers"),
    };
}

template<>
ItemPolicy VarDeserializer::deserialize<ItemPolicy>(const Poco::Dynamic::Var& val, const std::string& name) {
    TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    return {
        .get = deserialize<std::string>(obj->get("get"), name + ".get"),
        .listMy = deserialize<std::string>(obj->get("listMy"), name + ".listMy"),
        .listAll = deserialize<std::string>(obj->get("listAll"), name + ".listAll"),
        .create = deserialize<std::string>(obj->get("create"), name + ".create"),
        .update = deserialize<std::string>(obj->get("update"), name + ".update"),
        .delete_ = deserialize<std::string>(obj->get("delete_"), name + ".delete_"),
    };
}

template<>
ContainerPolicy VarDeserializer::deserialize<ContainerPolicy>(const Poco::Dynamic::Var& val, const std::string& name) {
    TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    ContainerPolicy result {};
    result.get = deserializeOptional<std::string>(obj->get("get"), name + ".get");
    result.update = deserializeOptional<std::string>(obj->get("update"), name + ".update");
    result.delete_ = deserializeOptional<std::string>(obj->get("delete_"), name + ".delete_");
    result.updatePolicy = deserializeOptional<std::string>(obj->get("updatePolicy"), name + ".updatePolicy");
    result.updaterCanBeRemovedFromManagers = deserializeOptional<std::string>(obj->get("updaterCanBeRemovedFromManagers"), name + ".updaterCanBeRemovedFromManagers");
    result.ownerCanBeRemovedFromManagers = deserializeOptional<std::string>(obj->get("ownerCanBeRemovedFromManagers"), name + ".ownerCanBeRemovedFromManagers");
    result.item = deserializeOptional<ItemPolicy>(obj->get("item"), name + ".item");
    return result;
}

template<>
PKIVerificationOptions VarDeserializer::deserialize<PKIVerificationOptions>(const Poco::Dynamic::Var& val, const std::string& name) {
    TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    PKIVerificationOptions result {};
    result.bridgePubKey = deserializeOptional<std::string>(obj->get("bridgePubKey"), name + ".get");
    result.bridgeInstanceId = deserializeOptional<std::string>(obj->get("bridgeInstanceId"), name + ".update");
    return result;
}