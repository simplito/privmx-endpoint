/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/stream/StreamVarSerializer.hpp"

#include <Poco/JSON/Array.h>
#include <Poco/JSON/Object.h>

using namespace privmx::endpoint;
using namespace privmx::endpoint::core;

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::Settings>(const stream::Settings& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::TurnCredentials>(const stream::TurnCredentials& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "stream$TurnCredentials");
    }
    obj->set("url", serialize(val.url));
    obj->set("username", serialize(val.username));
    obj->set("password", serialize(val.password));
    obj->set("expirationTime", serialize(val.expirationTime));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::Stream>(const stream::Stream& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "stream$Stream");
    }
    obj->set("streamId", serialize(val.streamId));
    obj->set("userId", serialize(val.userId));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<core::PagingList<stream::StreamRoom>>(const core::PagingList<stream::StreamRoom>& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "core$PagingList<stream$StreamRoom>");
    }
    obj->set("totalAvailable", serialize(val.totalAvailable));
    obj->set("readItems", serialize(val.readItems));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamRoom>(const stream::StreamRoom& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "stream$StreamRoom");
    }
    obj->set("streamRoomId", serialize(val.streamRoomId));
    obj->set("contextId", serialize(val.contextId));
    obj->set("createDate", serialize(val.createDate));
    obj->set("creator", serialize(val.creator));
    obj->set("lastModificationDate", serialize(val.lastModificationDate));
    obj->set("lastModifier", serialize(val.lastModifier));
    obj->set("users", serialize(val.users));
    obj->set("managers", serialize(val.managers));
    obj->set("version", serialize(val.version));
    obj->set("publicMeta", serialize(val.publicMeta));
    obj->set("privateMeta", serialize(val.privateMeta));
    obj->set("policy", serialize(val.policy));
    return obj;
}