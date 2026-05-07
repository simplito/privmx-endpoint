/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/core/VarSerializer.hpp"

#include <Poco/JSON/Array.h>
#include <Poco/JSON/Object.h>

#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/core/Validator.hpp"

using namespace privmx::endpoint::core;

// primitives

template<>
Poco::Dynamic::Var VarSerializer::serialize<int64_t>(const int64_t& val) {
    return Poco::Int64(val);
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<std::string>(const std::string& val) {
    return val;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<Buffer>(const core::Buffer& val) {
    switch (_options.binaryFormat) {
        case VarSerializer::Options::CORE_BUFFER:
            return val;
        case VarSerializer::Options::PSON_BINARYSTRING:
            return Pson::BinaryString(val.stdString());
        case VarSerializer::Options::STD_STRING_AS_BASE64:
            return utils::Base64::from(val.stdString());
        case VarSerializer::Options::STD_STRING:
            return val.stdString();
    }
    throw UnsupportedSerializerBinaryFormatException();
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<bool>(const bool& val) {
    return val;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize(const std::map<std::string, bool>& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "map<string,bool>");
    }
    for (const auto& item : val) {
        obj->set(item.first, serialize(item.second));
    }
    return obj;
}

// serializeBase<Event> stays here — non-inline, called by inline event serializers in VarSerialization.hpp

template<>
Poco::JSON::Object::Ptr VarSerializer::serializeBase<Event>(const Event& val, const std::string& type) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", type);
    }
    obj->set("type", serialize(val.type));
    obj->set("channel", serialize(val.channel));
    obj->set("connectionId", serialize(val.connectionId));
    obj->set("subscriptions", serialize(val.subscriptions));
    obj->set("timestamp", serialize(val.timestamp));
    return obj;
}
