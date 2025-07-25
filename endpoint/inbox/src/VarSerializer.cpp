/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/inbox/VarSerializer.hpp"
#include <privmx/endpoint/thread/VarSerializer.hpp>
#include <privmx/endpoint/store/VarSerializer.hpp>

#include <Poco/JSON/Array.h>
#include <Poco/JSON/Object.h>

using namespace privmx::endpoint;
using namespace privmx::endpoint::core;

template<>
Poco::Dynamic::Var VarSerializer::serialize<inbox::FilesConfig>(const inbox::FilesConfig& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "inbox$FilesConfig");
    }
    obj->set("minCount", serialize(val.minCount));
    obj->set("maxCount", serialize(val.maxCount));
    obj->set("maxFileSize", serialize(val.maxFileSize));
    obj->set("maxWholeUploadSize", serialize(val.maxWholeUploadSize));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<inbox::InboxPublicView>(const inbox::InboxPublicView& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "inbox$InboxPublicView");
    }
    obj->set("inboxId", serialize(val.inboxId));
    obj->set("version", serialize(val.version));
    obj->set("publicMeta", serialize(val.publicMeta));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<inbox::Inbox>(const inbox::Inbox& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "inbox$Inbox");
    }
    obj->set("inboxId", serialize(val.inboxId));
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
    obj->set("filesConfig", serialize(val.filesConfig));
    obj->set("policy", serialize(val.policy));
    obj->set("statusCode", serialize(val.statusCode));
    obj->set("schemaVersion", serialize(val.schemaVersion));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<core::PagingList<inbox::Inbox>>(const core::PagingList<inbox::Inbox>& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "core$PagingList<inbox$Inbox>");
    }
    obj->set("totalAvailable", serialize(val.totalAvailable));
    obj->set("readItems", serialize(val.readItems));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<inbox::InboxEntry>(const inbox::InboxEntry& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "inbox$InboxEntry");
    }
    obj->set("entryId", serialize(val.entryId));
    obj->set("inboxId", serialize(val.inboxId));
    obj->set("data", serialize(val.data));
    obj->set("files", serialize(val.files));
    obj->set("authorPubKey", serialize(val.authorPubKey));
    obj->set("createDate", serialize(val.createDate));
    obj->set("statusCode", serialize(val.statusCode));
    obj->set("schemaVersion", serialize(val.schemaVersion));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<core::PagingList<inbox::InboxEntry>>(const core::PagingList<inbox::InboxEntry>& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "core$PagingList<inbox$InboxEntry>");
    }
    obj->set("totalAvailable", serialize(val.totalAvailable));
    obj->set("readItems", serialize(val.readItems));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<inbox::InboxCreatedEvent>(const inbox::InboxCreatedEvent& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "inbox$InboxCreatedEvent");
    }
    obj->set("type", serialize(val.type));
    obj->set("channel", serialize(val.channel));
    obj->set("connectionId", serialize(val.connectionId));
    obj->set("data", serialize(val.data));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<inbox::InboxUpdatedEvent>(const inbox::InboxUpdatedEvent& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "inbox$InboxUpdatedEvent");
    }
    obj->set("type", serialize(val.type));
    obj->set("channel", serialize(val.channel));
    obj->set("connectionId", serialize(val.connectionId));
    obj->set("data", serialize(val.data));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<inbox::InboxDeletedEventData>(const inbox::InboxDeletedEventData& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "inbox$InboxDeletedEventData");
    }
    obj->set("inboxId", serialize(val.inboxId));
    return obj;
}


template<>
Poco::Dynamic::Var VarSerializer::serialize<inbox::InboxDeletedEvent>(const inbox::InboxDeletedEvent& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "inbox$InboxDeletedEvent");
    }
    obj->set("type", serialize(val.type));
    obj->set("channel", serialize(val.channel));
    obj->set("connectionId", serialize(val.connectionId));
    obj->set("data", serialize(val.data));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<inbox::InboxEntryCreatedEvent>(const inbox::InboxEntryCreatedEvent& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "inbox$InboxEntryCreatedEvent");
    }
    obj->set("type", serialize(val.type));
    obj->set("channel", serialize(val.channel));
    obj->set("connectionId", serialize(val.connectionId));
    obj->set("data", serialize(val.data));
    return obj;
}


template<>
Poco::Dynamic::Var VarSerializer::serialize<inbox::InboxEntryDeletedEventData>(const inbox::InboxEntryDeletedEventData& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "inbox$InboxEntryDeletedEventData");
    }
    obj->set("inboxId", serialize(val.inboxId));
    obj->set("entryId", serialize(val.entryId));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<inbox::InboxEntryDeletedEvent>(const inbox::InboxEntryDeletedEvent& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "inbox$InboxEntryDeletedEvent");
    }
    obj->set("type", serialize(val.type));
    obj->set("channel", serialize(val.channel));
    obj->set("connectionId", serialize(val.connectionId));
    obj->set("data", serialize(val.data));
    return obj;
}
