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
    obj->set("publicMetaVersion", serialize(val.publicMetaVersion));
    obj->set("privateMetaVersion", serialize(val.privateMetaVersion));
    obj->set("rosterVersion", serialize(val.rosterVersion));
    obj->set("publicMeta", serialize(val.publicMeta));
    obj->set("privateMeta", serialize(val.privateMeta));
    obj->set("policy", serialize(val.policy));
    obj->set("statusCode", serialize(val.statusCode));
    obj->set("schemaVersion", serialize(val.schemaVersion));
    obj->set("keyVersion", serialize(val.keyVersion));
    obj->set("visibleTo", serialize(val.visibleTo));
    obj->set("rules", serialize(val.rules));
    if (val.type.has_value()) {
        obj->set("type", serialize(val.type.value()));
    }
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::EnvelopeAuthor>(const group::EnvelopeAuthor& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "group$EnvelopeAuthor");
    }
    obj->set("userId", serialize(val.userId));
    obj->set("pubKey", serialize(val.pubKey));
    obj->set("role", serialize(val.role));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::EnvelopeSender>(const group::EnvelopeSender& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "group$EnvelopeSender");
    }
    obj->set("userId", serialize(val.userId));
    obj->set("pubKey", serialize(val.pubKey));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::EnvelopeAudience>(const group::EnvelopeAudience& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "group$EnvelopeAudience");
    }
    obj->set("groups", serialize(val.groups));
    obj->set("users", serialize(val.users));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::DecryptedEnvelope>(const group::DecryptedEnvelope& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "group$DecryptedEnvelope");
    }
    obj->set("data", serialize(val.data));
    obj->set("author", serialize(val.author));
    obj->set("keyVersion", serialize(val.keyVersion));
    obj->set("encryptedAt", serialize(val.encryptedAt));
    obj->set("sharedWith", serialize(val.sharedWith));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::GroupErrorDetails>(const group::GroupErrorDetails& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "group$GroupErrorDetails");
    }
    obj->set("userId", serialize(val.userId));
    obj->set("pubKey", serialize(val.pubKey));
    obj->set("envelopeKind", serialize(val.envelopeKind));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::DecryptResult>(const group::DecryptResult& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "group$DecryptResult");
    }
    obj->set("statusCode", serialize(val.statusCode));
    obj->set("envelope", serialize(val.envelope));
    obj->set("details", serialize(val.details));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::DecryptedOutsiderEnvelope>(
    const group::DecryptedOutsiderEnvelope& val
) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "group$DecryptedOutsiderEnvelope");
    }
    obj->set("data", serialize(val.data));
    obj->set("keyVersion", serialize(val.keyVersion));
    obj->set("sender", serialize(val.sender));
    obj->set("encryptedAt", serialize(val.encryptedAt));
    obj->set("sharedWith", serialize(val.sharedWith));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::DecryptedAnonymousEnvelope>(
    const group::DecryptedAnonymousEnvelope& val
) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "group$DecryptedAnonymousEnvelope");
    }
    obj->set("data", serialize(val.data));
    obj->set("keyVersion", serialize(val.keyVersion));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::DecryptedSharedEnvelope>(const group::DecryptedSharedEnvelope& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "group$DecryptedSharedEnvelope");
    }
    obj->set("data", serialize(val.data));
    obj->set("sender", serialize(val.sender));
    obj->set("homeGroupId", serialize(val.homeGroupId));
    obj->set("senderMembership", serialize(val.senderMembership));
    obj->set("via", serialize(val.via));
    obj->set("encryptedAt", serialize(val.encryptedAt));
    obj->set("sharedWith", serialize(val.sharedWith));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::GroupEpochRef>(const group::GroupEpochRef& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "group$GroupEpochRef");
    }
    obj->set("groupId", serialize(val.groupId));
    obj->set("keyVersion", serialize(val.keyVersion));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::EnvelopeHeader>(const group::EnvelopeHeader& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "group$EnvelopeHeader");
    }
    obj->set("version", serialize(val.version));
    obj->set("groupId", serialize(val.groupId));
    obj->set("keyVersion", serialize(val.keyVersion));
    obj->set("fromOutsider", serialize(val.fromOutsider));
    obj->set("isSigned", serialize(val.isSigned));
    obj->set("isFile", serialize(val.isFile));
    obj->set("hasLocation", serialize(val.hasLocation));
    obj->set("authorUserId", serialize(val.authorUserId));
    obj->set("sequenceId", serialize(val.sequenceId));
    obj->set("spaceId", serialize(val.spaceId));
    obj->set("alsoForGroups", serialize(val.alsoForGroups));
    obj->set("alsoForUsers", serialize(val.alsoForUsers));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::PathSegment>(const group::PathSegment& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "group$PathSegment");
    }
    obj->set("isId", serialize(val.isId));
    obj->set("value", serialize(val.value));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::DecryptedFileInfo>(const group::DecryptedFileInfo& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "group$DecryptedFileInfo");
    }
    if (val.author.has_value()) {
        obj->set("author", serialize(val.author.value()));
    }
    if (val.sender.has_value()) {
        obj->set("sender", serialize(val.sender.value()));
    }
    obj->set("homeGroupId", serialize(val.homeGroupId));
    obj->set("senderMembership", serialize(val.senderMembership));
    obj->set("via", serialize(val.via));
    obj->set("sharedWith", serialize(val.sharedWith));
    obj->set("keyVersion", serialize(val.keyVersion));
    obj->set("size", serialize(val.size));
    obj->set("complete", serialize(val.complete));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::SpaceGroupRecipient>(const group::SpaceGroupRecipient& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "group$SpaceGroupRecipient");
    }
    obj->set("groupId", serialize(val.groupId));
    obj->set("role", serialize(val.role));
    obj->set("keyVersion", serialize(val.keyVersion));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::SpaceUserRecipient>(const group::SpaceUserRecipient& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "group$SpaceUserRecipient");
    }
    obj->set("userId", serialize(val.userId));
    obj->set("pubKey", serialize(val.pubKey));
    obj->set("role", serialize(val.role));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::SpaceState>(const group::SpaceState& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "group$SpaceState");
    }
    obj->set("spaceId", serialize(val.spaceId));
    obj->set("contextId", serialize(val.contextId));
    obj->set("createdBy", serialize(val.createdBy));
    obj->set("groups", serialize(val.groups));
    obj->set("users", serialize(val.users));
    obj->set("keyVersion", serialize(val.keyVersion));
    obj->set("keyIsStale", serialize(val.keyIsStale));
    obj->set("publicMeta", serialize(val.publicMeta));
    obj->set("privateMeta", serialize(val.privateMeta));
    obj->set("publicMetaVersion", serialize(val.publicMetaVersion));
    obj->set("privateMetaVersion", serialize(val.privateMetaVersion));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::SpaceOrigin>(const group::SpaceOrigin& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "group$SpaceOrigin");
    }
    obj->set("author", serialize(val.author));
    obj->set("via", serialize(val.via));
    obj->set("authorAccess", serialize(val.authorAccess));
    obj->set("keyVersion", serialize(val.keyVersion));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::DecryptedSpaceEnvelope>(const group::DecryptedSpaceEnvelope& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "group$DecryptedSpaceEnvelope");
    }
    obj->set("data", serialize(val.data));
    obj->set("origin", serialize(val.origin));
    obj->set("encryptedAt", serialize(val.encryptedAt));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::SpaceDecryptResult>(const group::SpaceDecryptResult& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "group$SpaceDecryptResult");
    }
    obj->set("statusCode", serialize(val.statusCode));
    obj->set("envelope", serialize(val.envelope));
    obj->set("details", serialize(val.details));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<core::PagingList<group::SpaceState>>(
    const core::PagingList<group::SpaceState>& val
) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "core$PagingList<group$SpaceState>");
    }
    obj->set("totalAvailable", serialize(val.totalAvailable));
    obj->set("readItems", serialize(val.readItems));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::CipherRange>(const group::CipherRange& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "group$CipherRange");
    }
    obj->set("offset", serialize(val.offset));
    obj->set("length", serialize(val.length));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::SequenceItemHeader>(const group::SequenceItemHeader& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "group$SequenceItemHeader");
    }
    obj->set("sequenceId", serialize(val.sequenceId));
    obj->set("index", serialize(val.index));
    obj->set("isMark", serialize(val.isMark));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::SequenceAppendResult>(const group::SequenceAppendResult& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "group$SequenceAppendResult");
    }
    obj->set("item", serialize(val.item));
    if (val.mark.has_value()) {
        obj->set("mark", serialize(val.mark.value()));
    }
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::SequenceItem>(const group::SequenceItem& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "group$SequenceItem");
    }
    obj->set("data", serialize(val.data));
    obj->set("index", serialize(val.index));
    obj->set("missing", serialize(val.missing));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::SequenceMarkInfo>(const group::SequenceMarkInfo& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "group$SequenceMarkInfo");
    }
    obj->set("attestedItems", serialize(val.attestedItems));
    obj->set("closed", serialize(val.closed));
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
    obj->set("publicMetaVersion", serialize(val.publicMetaVersion));
    obj->set("privateMetaVersion", serialize(val.privateMetaVersion));
    obj->set("rosterVersion", serialize(val.rosterVersion));
    obj->set("policy", serialize(val.policy));
    obj->set("keyVersion", serialize(val.keyVersion));
    obj->set("visibleTo", serialize(val.visibleTo));
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
    obj->set("publicMetaVersion", serialize(val.publicMetaVersion));
    obj->set("privateMetaVersion", serialize(val.privateMetaVersion));
    obj->set("rosterVersion", serialize(val.rosterVersion));
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

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::GroupCustomEventData>(const group::GroupCustomEventData& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "group$GroupCustomEventData");
    }
    obj->set("groupId", serialize(val.groupId));
    obj->set("channelName", serialize(val.channelName));
    obj->set("userId", serialize(val.userId));
    obj->set("authorPubKey", serialize(val.authorPubKey));
    obj->set("payload", serialize(val.payload));
    obj->set("statusCode", serialize(val.statusCode));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::GroupCustomEvent>(const group::GroupCustomEvent& val) {
    return serializeBaseWithData<Event>(val, "group$GroupCustomEvent");
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::GroupResult>(const group::GroupResult& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "group$GroupResult");
    }
    obj->set("statusCode", serialize(val.statusCode));
    obj->set("group", serialize(val.group));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::GroupRules>(const group::GroupRules& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "group$GroupRules");
    }
    obj->set("addMembers", serialize(val.addMembers));
    obj->set("removeMembers", serialize(val.removeMembers));
    obj->set("updateMeta", serialize(val.updateMeta));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::GroupLogEntry>(const group::GroupLogEntry& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "group$GroupLogEntry");
    }
    obj->set("seq", serialize(val.seq));
    obj->set("kind", serialize(val.kind));
    obj->set("author", serialize(val.author));
    obj->set("authorPubKey", serialize(val.authorPubKey));
    obj->set("date", serialize(val.date));
    obj->set("keyVersion", serialize(val.keyVersion));
    obj->set("rosterVersion", serialize(val.rosterVersion));
    obj->set("addedUsers", serialize(val.addedUsers));
    obj->set("addedManagers", serialize(val.addedManagers));
    obj->set("removed", serialize(val.removed));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<core::PagingList<group::GroupLogEntry>>(
    const core::PagingList<group::GroupLogEntry>& val
) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "core$PagingList<group$GroupLogEntry>");
    }
    obj->set("totalAvailable", serialize(val.totalAvailable));
    obj->set("readItems", serialize(val.readItems));
    return obj;
}

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::GroupPublicKey>(const group::GroupPublicKey& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "group$GroupPublicKey");
    }
    obj->set("groupId", serialize(val.groupId));
    obj->set("keyVersion", serialize(val.keyVersion));
    obj->set("pubKey", serialize(val.pubKey));
    obj->set("creator", serialize(val.creator));
    return obj;
}
