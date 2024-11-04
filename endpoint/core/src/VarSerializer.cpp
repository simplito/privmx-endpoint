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

// core

template<>
Poco::Dynamic::Var VarSerializer::serialize<Context>(const Context& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "core$Context");
    }
    obj->set("userId", serialize(val.userId));
    obj->set("contextId", serialize(val.contextId));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<PagingList<Context>>(const PagingList<Context>& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "core$PagingList<core$Context>");
    }
    obj->set("totalAvailable", serialize(val.totalAvailable));
    obj->set("readItems", serialize(val.readItems));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<LibPlatformDisconnectedEvent>(const LibPlatformDisconnectedEvent& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "core$LibPlatformDisconnectedEvent");
    }
    obj->set("type", serialize(val.type));
    obj->set("channel", serialize(val.channel));
    obj->set("connectionId", serialize(val.connectionId));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<LibConnectedEvent>(const LibConnectedEvent& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "core$LibConnectedEvent");
    }
    obj->set("type", serialize(val.type));
    obj->set("channel", serialize(val.channel));
    obj->set("connectionId", serialize(val.connectionId));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<LibDisconnectedEvent>(const LibDisconnectedEvent& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "core$LibDisconnectedEvent");
    }
    obj->set("type", serialize(val.type));
    obj->set("channel", serialize(val.channel));
    obj->set("connectionId", serialize(val.connectionId));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<LibBreakEvent>(const LibBreakEvent& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "core$LibBreakEvent");
    }
    obj->set("type", serialize(val.type));
    obj->set("channel", serialize(val.channel));
    obj->set("connectionId", serialize(val.connectionId));
    return obj;
}
