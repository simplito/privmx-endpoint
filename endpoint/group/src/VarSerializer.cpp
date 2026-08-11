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
    // The epoch. Wrappers need it: it is what tells a caller whether a container granted to this group has to be
    // re-keyed, and it is the value every tree/ladder operation is ordered by.
    obj->set("keyVersion", serialize(val.keyVersion));
    if (val.type.has_value()) {
        obj->set("type", serialize(val.type.value()));
    }
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<core::PagingList<group::Group>>(
    const core::PagingList<group::Group>& val
) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "core$PagingList<group$Group>");
    }
    obj->set("totalAvailable", serialize(val.totalAvailable));
    obj->set("readItems", serialize(val.readItems));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::GroupDeletedEventData>(
    const group::GroupDeletedEventData& val
) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "group$GroupDeletedEventData");
    }
    obj->set("groupId", serialize(val.groupId));
    obj->set("contextId", serialize(val.contextId));
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
