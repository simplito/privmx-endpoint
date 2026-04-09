/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/search/VarSerializer.hpp"
#include "privmx/endpoint/search/Types.hpp"

#include <Poco/JSON/Array.h>
#include <Poco/JSON/Object.h>

using namespace privmx::endpoint;
using namespace privmx::endpoint::core;



template<>
Poco::Dynamic::Var VarSerializer::serialize<core::PagingList<search::SearchIndex>>(const core::PagingList<search::SearchIndex>& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "core$PagingList<search$SearchIndex>");
    }
    obj->set("totalAvailable", serialize(val.totalAvailable));
    obj->set("readItems", serialize(val.readItems));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<core::PagingList<search::Document>>(const core::PagingList<search::Document>& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "core$PagingList<search$Document>");
    }
    obj->set("totalAvailable", serialize(val.totalAvailable));
    obj->set("readItems", serialize(val.readItems));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<search::IndexMode>(const search::IndexMode& val) {
    return Poco::Dynamic::Var(static_cast<int64_t>(val));
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<search::SearchIndex>(const search::SearchIndex& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "search$SearchIndex");
    }
    obj->set("contextId", serialize(val.contextId));
    obj->set("indexId", serialize(val.indexId));
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
    obj->set("mode", serialize(val.mode));
    obj->set("statusCode", serialize(val.statusCode));
    obj->set("schemaVersion", serialize(val.schemaVersion));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<search::Document>(const search::Document& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "search$Document");
    }
    obj->set("documentId", serialize(val.documentId));
    obj->set("name", serialize(val.name));
    obj->set("content", serialize(val.content));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<search::NewDocument>(const search::NewDocument& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "search$NewDocument");
    }
    obj->set("name", serialize(val.name));
    obj->set("content", serialize(val.content));
    return obj;
}
