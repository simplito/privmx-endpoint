#include "privmx/endpoint/group/VarSerializer.hpp"

#include <Poco/JSON/Array.h>
#include <Poco/JSON/Object.h>

using namespace privmx::endpoint;
using namespace privmx::endpoint::core;

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::Group>(const group::Group& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "group$Group");
    }
    obj->set("contextId", serialize(val.contextId));
    obj->set("groupId", serialize(val.groupId));
    obj->set("groupPubKey", serialize(val.groupPubKey));
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
    obj->set("statusCode", serialize(val.statusCode));
    obj->set("schemaVersion", serialize(val.schemaVersion));
    obj->set("keyVersion", serialize(val.keyVersion));
    if (val.type.has_value()) {
        obj->set("type", serialize(val.type.value()));
    }
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::DecryptedEnvelope>(const group::DecryptedEnvelope& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "group$DecryptedEnvelope");
    }
    obj->set("data", serialize(val.data));
    obj->set("groupId", serialize(val.groupId));
    obj->set("authorPubKey", serialize(val.authorPubKey));
    obj->set("type", serialize((int64_t)val.type));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::DecryptedFileInfo>(const group::DecryptedFileInfo& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "group$DecryptedFileInfo");
    }
    obj->set("groupId", serialize(val.groupId));
    obj->set("authorPubKey", serialize(val.authorPubKey));
    obj->set("type", serialize((int64_t)val.type));
    obj->set("complete", serialize(val.complete));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::GroupSummary>(const group::GroupSummary& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "group$GroupSummary");
    }
    obj->set("contextId", serialize(val.contextId));
    obj->set("groupId", serialize(val.groupId));
    obj->set("groupPubKey", serialize(val.groupPubKey));
    obj->set("createDate", serialize(val.createDate));
    obj->set("creator", serialize(val.creator));
    obj->set("lastModificationDate", serialize(val.lastModificationDate));
    obj->set("lastModifier", serialize(val.lastModifier));
    obj->set("users", serialize(val.users));
    obj->set("managers", serialize(val.managers));
    obj->set("version", serialize(val.version));
    obj->set("policy", serialize(val.policy));
    obj->set("keyVersion", serialize(val.keyVersion));
    if (val.type.has_value()) {
        obj->set("type", serialize(val.type.value()));
    }
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<core::PagingList<group::GroupSummary>>(
    const core::PagingList<group::GroupSummary>& val
) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "core$PagingList<group$GroupSummary>");
    }
    obj->set("totalAvailable", serialize(val.totalAvailable));
    obj->set("readItems", serialize(val.readItems));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::GroupDeletedEventData>(const group::GroupDeletedEventData& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "group$GroupDeletedEventData");
    }
    obj->set("groupId", serialize(val.groupId));
    obj->set("contextId", serialize(val.contextId));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::GroupChangedEventData>(const group::GroupChangedEventData& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "group$GroupChangedEventData");
    }
    obj->set("groupId", serialize(val.groupId));
    obj->set("contextId", serialize(val.contextId));
    obj->set("version", serialize(val.version));
    obj->set("keyVersion", serialize(val.keyVersion));
    obj->set("changeKind", serialize(val.changeKind));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::GroupCreatedEvent>(const group::GroupCreatedEvent& val) {
    return serializeBaseWithData<Event>(val, "group$GroupCreatedEvent");
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::GroupUpdatedEvent>(const group::GroupUpdatedEvent& val) {
    return serializeBaseWithData<Event>(val, "group$GroupUpdatedEvent");
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::GroupDeletedEvent>(const group::GroupDeletedEvent& val) {
    return serializeBaseWithData<Event>(val, "group$GroupDeletedEvent");
}
