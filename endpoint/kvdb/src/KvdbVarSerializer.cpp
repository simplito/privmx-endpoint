/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/kvdb/KvdbVarSerializer.hpp"

#include <Poco/JSON/Array.h>
#include <Poco/JSON/Object.h>

using namespace privmx::endpoint;
using namespace privmx::endpoint::core;

template<>
Poco::Dynamic::Var VarSerializer::serialize<kvdb::Kvdb>(const kvdb::Kvdb& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "kvdb$Kvdb");
    }
    obj->set("contextId", serialize(val.contextId));
    obj->set("kvdbId", serialize(val.kvdbId));
    obj->set("createDate", serialize(val.createDate));
    obj->set("creator", serialize(val.creator));
    obj->set("lastModificationDate", serialize(val.lastModificationDate));
    obj->set("lastModifier", serialize(val.lastModifier));
    obj->set("users", serialize(val.users));
    obj->set("managers", serialize(val.managers));
    obj->set("version", serialize(val.version));
    obj->set("privateMeta", serialize(val.privateMeta));
    obj->set("publicMeta", serialize(val.publicMeta));
    obj->set("policy", serialize(val.policy));
    obj->set("statusCode", serialize(val.statusCode));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<core::PagingList<kvdb::Kvdb>>(const core::PagingList<kvdb::Kvdb>& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "core$PagingList<kvdb$Kvdb>");
    }
    obj->set("totalAvailable", serialize(val.totalAvailable));
    obj->set("readItems", serialize(val.readItems));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<kvdb::ServerItemInfo>(const kvdb::ServerItemInfo& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "kvdb$ServerItemInfo");
    }
    obj->set("kvdbId", serialize(val.kvdbId));
    obj->set("messageId", serialize(val.key));
    obj->set("createDate", serialize(val.createDate));
    obj->set("author", serialize(val.author));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<kvdb::Item>(const kvdb::Item& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "kvdb$Item");
    }
    obj->set("info", serialize(val.info));
    obj->set("publicMeta", serialize(val.publicMeta));
    obj->set("privateMeta", serialize(val.privateMeta));
    obj->set("data", serialize(val.data));
    obj->set("authorPubKey", serialize(val.authorPubKey));
    obj->set("statusCode", serialize(val.statusCode));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<PagingList<kvdb::Item>>(const PagingList<kvdb::Item>& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "core$PagingList<kvdb$Item>");
    }
    obj->set("totalAvailable", serialize(val.totalAvailable));
    obj->set("readItems", serialize(val.readItems));
    return obj;
}


template<>
Poco::Dynamic::Var VarSerializer::serialize<kvdb::KvdbDeletedEventData>(const kvdb::KvdbDeletedEventData& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "kvdb$KvdbDeletedEventData");
    }
    obj->set("kvdbId", serialize(val.kvdbId));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<kvdb::KvdbStatsEventData>(const kvdb::KvdbStatsEventData& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "kvdb$KvdbStatsEventData");
    }
    obj->set("kvdbId", serialize(val.kvdbId));
    obj->set("lastItemDate", serialize(val.lastItemDate));
    obj->set("items", serialize(val.items));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<kvdb::KvdbDeletedItemEventData>(
    const kvdb::KvdbDeletedItemEventData& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "kvdb$KvdbDeletedItemEventData");
    }
    obj->set("kvdbId", serialize(val.kvdbId));
    obj->set("kvdbItemKey", serialize(val.kvdbItemKey));
    return obj;
}


template<>
Poco::Dynamic::Var VarSerializer::serialize<kvdb::KvdbCreatedEvent>(const kvdb::KvdbCreatedEvent& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "kvdb$KvdbCreatedEvent");
    }
    obj->set("type", serialize(val.type));
    obj->set("channel", serialize(val.channel));
    obj->set("connectionId", serialize(val.connectionId));
    obj->set("data", serialize(val.data));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<kvdb::KvdbUpdatedEvent>(const kvdb::KvdbUpdatedEvent& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "kvdb$KvdbUpdatedEvent");
    }
    obj->set("type", serialize(val.type));
    obj->set("channel", serialize(val.channel));
    obj->set("connectionId", serialize(val.connectionId));
    obj->set("data", serialize(val.data));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<kvdb::KvdbDeletedEvent>(const kvdb::KvdbDeletedEvent& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "kvdb$KvdbDeletedEvent");
    }
    obj->set("type", serialize(val.type));
    obj->set("channel", serialize(val.channel));
    obj->set("connectionId", serialize(val.connectionId));
    obj->set("data", serialize(val.data));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<kvdb::KvdbStatsChangedEvent>(const kvdb::KvdbStatsChangedEvent& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "kvdb$KvdbStatsChangedEvent");
    }
    obj->set("type", serialize(val.type));
    obj->set("channel", serialize(val.channel));
    obj->set("connectionId", serialize(val.connectionId));
    obj->set("data", serialize(val.data));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<kvdb::KvdbNewItemEvent>(const kvdb::KvdbNewItemEvent& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "kvdb$KvdbNewItemEvent");
    }
    obj->set("type", serialize(val.type));
    obj->set("channel", serialize(val.channel));
    obj->set("connectionId", serialize(val.connectionId));
    obj->set("data", serialize(val.data));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<kvdb::KvdbItemUpdatedEvent>(const kvdb::KvdbItemUpdatedEvent& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "kvdb$KvdbItemUpdatedEvent");
    }
    obj->set("type", serialize(val.type));
    obj->set("channel", serialize(val.channel));
    obj->set("connectionId", serialize(val.connectionId));
    obj->set("data", serialize(val.data));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<kvdb::KvdbItemDeletedEvent>(
    const kvdb::KvdbItemDeletedEvent& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "kvdb$KvdbItemDeletedEvent");
    }
    obj->set("type", serialize(val.type));
    obj->set("channel", serialize(val.channel));
    obj->set("connectionId", serialize(val.connectionId));
    obj->set("data", serialize(val.data));
    return obj;
}


