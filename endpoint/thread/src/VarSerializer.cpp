/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/thread/VarSerializer.hpp"

#include <Poco/JSON/Array.h>
#include <Poco/JSON/Object.h>

using namespace privmx::endpoint;
using namespace privmx::endpoint::core;

template<>
Poco::Dynamic::Var VarSerializer::serialize<thread::Thread>(const thread::Thread& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "thread$Thread");
    }
    obj->set("contextId", serialize(val.contextId));
    obj->set("threadId", serialize(val.threadId));
    obj->set("createDate", serialize(val.createDate));
    obj->set("creator", serialize(val.creator));
    obj->set("lastModificationDate", serialize(val.lastModificationDate));
    obj->set("lastModifier", serialize(val.lastModifier));
    obj->set("users", serialize(val.users));
    obj->set("managers", serialize(val.managers));
    obj->set("schemaVersion", serialize(val.schemaVersion));
    obj->set("version", serialize(val.version));
    obj->set("lastMsgDate", serialize(val.lastMsgDate));
    obj->set("privateMeta", serialize(val.privateMeta));
    obj->set("publicMeta", serialize(val.publicMeta));
    obj->set("policy", serialize(val.policy));
    obj->set("messagesCount", serialize(val.messagesCount));
    obj->set("statusCode", serialize(val.statusCode));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<core::PagingList<thread::Thread>>(const core::PagingList<thread::Thread>& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "core$PagingList<thread$Tread>");
    }
    obj->set("totalAvailable", serialize(val.totalAvailable));
    obj->set("readItems", serialize(val.readItems));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<thread::ThreadDeletedEventData>(const thread::ThreadDeletedEventData& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "thread$ThreadDeletedEventData");
    }
    obj->set("threadId", serialize(val.threadId));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<thread::ThreadDeletedMessageEventData>(
    const thread::ThreadDeletedMessageEventData& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "thread$ThreadDeletedMessageEventData");
    }
    obj->set("threadId", serialize(val.threadId));
    obj->set("messageId", serialize(val.messageId));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<thread::ThreadStatsEventData>(const thread::ThreadStatsEventData& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "thread$ThreadStatsEventData");
    }
    obj->set("threadId", serialize(val.threadId));
    obj->set("lastMsgDate", serialize(val.lastMsgDate));
    obj->set("messagesCount", serialize(val.messagesCount));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<thread::ThreadCreatedEvent>(const thread::ThreadCreatedEvent& val) {
    return serializeBaseWithData<Event>(val, "thread$ThreadCreatedEvent");
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<thread::ThreadUpdatedEvent>(const thread::ThreadUpdatedEvent& val) {
    return serializeBaseWithData<Event>(val, "thread$ThreadUpdatedEvent");
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<thread::ThreadDeletedEvent>(const thread::ThreadDeletedEvent& val) {
    return serializeBaseWithData<Event>(val, "thread$ThreadDeletedEvent");
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<thread::ThreadNewMessageEvent>(const thread::ThreadNewMessageEvent& val) {
    return serializeBaseWithData<Event>(val, "thread$ThreadNewMessageEvent");
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<thread::ThreadMessageUpdatedEvent>(const thread::ThreadMessageUpdatedEvent& val) {
    return serializeBaseWithData<Event>(val, "thread$ThreadMessageUpdatedEvent");
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<thread::ThreadMessageDeletedEvent>(
    const thread::ThreadMessageDeletedEvent& val) {
    return serializeBaseWithData<Event>(val, "thread$ThreadMessageDeletedEvent");
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<thread::ThreadStatsChangedEvent>(const thread::ThreadStatsChangedEvent& val) {
    return serializeBaseWithData<Event>(val, "thread$ThreadStatsChangedEvent");
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<thread::ServerMessageInfo>(const thread::ServerMessageInfo& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "thread$ServerMessageInfo");
    }
    obj->set("threadId", serialize(val.threadId));
    obj->set("messageId", serialize(val.messageId));
    obj->set("createDate", serialize(val.createDate));
    obj->set("author", serialize(val.author));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<thread::Message>(const thread::Message& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "thread$Message");
    }
    obj->set("info", serialize(val.info));
    obj->set("publicMeta", serialize(val.publicMeta));
    obj->set("privateMeta", serialize(val.privateMeta));
    obj->set("data", serialize(val.data));
    obj->set("authorPubKey", serialize(val.authorPubKey));
    obj->set("statusCode", serialize(val.statusCode));
    obj->set("schemaVersion", serialize(val.schemaVersion));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<PagingList<thread::Message>>(const PagingList<thread::Message>& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "core$PagingList<thread$Message>");
    }
    obj->set("totalAvailable", serialize(val.totalAvailable));
    obj->set("readItems", serialize(val.readItems));
    return obj;
}
