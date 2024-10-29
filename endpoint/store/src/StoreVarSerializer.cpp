#include "privmx/endpoint/store/StoreVarSerializer.hpp"

#include <Poco/JSON/Array.h>
#include <Poco/JSON/Object.h>

using namespace privmx::endpoint;
using namespace privmx::endpoint::core;


template<>
Poco::Dynamic::Var VarSerializer::serialize<store::Store>(const store::Store& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "store$Store");
    }
    obj->set("contextId", serialize(val.contextId));
    obj->set("storeId", serialize(val.storeId));
    obj->set("createDate", serialize(val.createDate));
    obj->set("creator", serialize(val.creator));
    obj->set("lastModificationDate", serialize(val.lastModificationDate));
    obj->set("lastFileDate", serialize(val.lastFileDate));
    obj->set("lastModifier", serialize(val.lastModifier));
    obj->set("users", serialize(val.users));
    obj->set("managers", serialize(val.managers));
    obj->set("version", serialize(val.version));
    obj->set("privateMeta", serialize(val.privateMeta));
    obj->set("publicMeta", serialize(val.publicMeta));
    obj->set("filesCount", serialize(val.filesCount));
    obj->set("statusCode", serialize(val.statusCode));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<core::PagingList<store::Store>>(const core::PagingList<store::Store>& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "store$PagingList<store$Store>");
    }
    obj->set("totalAvailable", serialize(val.totalAvailable));
    obj->set("readItems", serialize(val.readItems));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<store::StoreDeletedEventData>(const store::StoreDeletedEventData& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "store$StoreDeletedEventData");
    }
    obj->set("storeId", serialize(val.storeId));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<store::StoreStatsChangedEventData>(
    const store::StoreStatsChangedEventData& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "store$StoreStatsChangedEventData");
    }
    obj->set("contextId", serialize(val.contextId));
    obj->set("storeId", serialize(val.storeId));
    obj->set("lastFileDate", serialize(val.lastFileDate));
    obj->set("filesCount", serialize(val.filesCount));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<store::StoreFileDeletedEventData>(
    const store::StoreFileDeletedEventData& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "store$StoreFileDeletedEventData");
    }
    obj->set("contextId", serialize(val.contextId));
    obj->set("storeId", serialize(val.storeId));
    obj->set("fileId", serialize(val.fileId));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<store::StoreCreatedEvent>(const store::StoreCreatedEvent& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "store$StoreCreatedEvent");
    }
    obj->set("type", serialize(val.type));
    obj->set("channel", serialize(val.channel));
    obj->set("connectionId", serialize(val.connectionId));
    obj->set("data", serialize(val.data));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<store::StoreUpdatedEvent>(const store::StoreUpdatedEvent& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "store$StoreUpdatedEvent");
    }
    obj->set("type", serialize(val.type));
    obj->set("channel", serialize(val.channel));
    obj->set("connectionId", serialize(val.connectionId));
    obj->set("data", serialize(val.data));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<store::StoreDeletedEvent>(const store::StoreDeletedEvent& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "store$StoreDeletedEvent");
    }
    obj->set("type", serialize(val.type));
    obj->set("channel", serialize(val.channel));
    obj->set("connectionId", serialize(val.connectionId));
    obj->set("data", serialize(val.data));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<store::StoreStatsChangedEvent>(const store::StoreStatsChangedEvent& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "store$StoreStatsChangedEvent");
    }
    obj->set("type", serialize(val.type));
    obj->set("channel", serialize(val.channel));
    obj->set("connectionId", serialize(val.connectionId));
    obj->set("data", serialize(val.data));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<store::StoreFileCreatedEvent>(const store::StoreFileCreatedEvent& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "store$StoreFileCreatedEvent");
    }
    obj->set("type", serialize(val.type));
    obj->set("channel", serialize(val.channel));
    obj->set("connectionId", serialize(val.connectionId));
    obj->set("data", serialize(val.data));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<store::StoreFileUpdatedEvent>(const store::StoreFileUpdatedEvent& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "store$StoreFileUpdatedEvent");
    }
    obj->set("type", serialize(val.type));
    obj->set("channel", serialize(val.channel));
    obj->set("connectionId", serialize(val.connectionId));
    obj->set("data", serialize(val.data));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<store::StoreFileDeletedEvent>(const store::StoreFileDeletedEvent& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "store$StoreFileDeletedEvent");
    }
    obj->set("type", serialize(val.type));
    obj->set("channel", serialize(val.channel));
    obj->set("connectionId", serialize(val.connectionId));
    obj->set("data", serialize(val.data));
    return obj;
}


template<>
Poco::Dynamic::Var VarSerializer::serialize<store::ServerFileInfo>(const store::ServerFileInfo& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "store$ServerFileInfo");
    }
    obj->set("storeId", serialize(val.storeId));
    obj->set("fileId", serialize(val.fileId));
    obj->set("createDate", serialize(val.createDate));
    obj->set("author", serialize(val.author));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<store::File>(const store::File& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "store$File");
    }
    obj->set("info", serialize(val.info));
    obj->set("publicMeta", serialize(val.publicMeta));
    obj->set("privateMeta", serialize(val.privateMeta));
    obj->set("size", serialize(val.size));
    obj->set("authorPubKey", serialize(val.authorPubKey));
    obj->set("statusCode", serialize(val.statusCode));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<PagingList<store::File>>(const PagingList<store::File>& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "core$PagingList<store$File>");
    }
    obj->set("totalAvailable", serialize(val.totalAvailable));
    obj->set("readItems", serialize(val.readItems));
    return obj;
}