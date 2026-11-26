#include "privmx/endpoint/group/varinterface/GroupApiVarInterface.hpp"

#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/core/varinterface/VarInterfaceUtil.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::group;

std::map<GroupApiVarInterface::METHOD, Poco::Dynamic::Var (GroupApiVarInterface::*)(const Poco::Dynamic::Var&)>
    GroupApiVarInterface::methodMap = {
        {Create, &GroupApiVarInterface::create},
        {CreateGroup, &GroupApiVarInterface::createGroup},
        {AddGroupMembers, &GroupApiVarInterface::addGroupMembers},
        {RemoveGroupMembers, &GroupApiVarInterface::removeGroupMembers},
        {DeleteGroup, &GroupApiVarInterface::deleteGroup},
        {GetGroup, &GroupApiVarInterface::getGroup},
        {ListGroups, &GroupApiVarInterface::listGroups},
        {SubscribeFor, &GroupApiVarInterface::subscribeFor},
        {UnsubscribeFrom, &GroupApiVarInterface::unsubscribeFrom},
        {BuildSubscriptionQuery, &GroupApiVarInterface::buildSubscriptionQuery},
        {Encrypt, &GroupApiVarInterface::encrypt},
        {Decrypt, &GroupApiVarInterface::decrypt},
        {EncryptAnonymously, &GroupApiVarInterface::encryptAnonymously},
        {BeginFileEncryption, &GroupApiVarInterface::beginFileEncryption},
        {EncryptFileChunk, &GroupApiVarInterface::encryptFileChunk},
        {BeginFileDecryption, &GroupApiVarInterface::beginFileDecryption},
        {DecryptFileChunk, &GroupApiVarInterface::decryptFileChunk},
        {FinishFileEncryption, &GroupApiVarInterface::finishFileEncryption},
        {FinishFileDecryption, &GroupApiVarInterface::finishFileDecryption},
        {BeginFileEncryptionAnonymously, &GroupApiVarInterface::beginFileEncryptionAnonymously},
        {SeekInEncryptedFile, &GroupApiVarInterface::seekInEncryptedFile},
        {SendCustomEvent, &GroupApiVarInterface::sendCustomEvent},
        {BuildCustomEventSubscriptionQuery, &GroupApiVarInterface::buildCustomEventSubscriptionQuery},
        {UpdateGroupPublicMeta, &GroupApiVarInterface::updateGroupPublicMeta},
        {UpdateGroupPrivateMeta, &GroupApiVarInterface::updateGroupPrivateMeta},
        {RotateGroupKey, &GroupApiVarInterface::rotateGroupKey},
        {RenewLeaf, &GroupApiVarInterface::renewLeaf},
        {DecryptMany, &GroupApiVarInterface::decryptMany},
        {EncryptAsOutsider, &GroupApiVarInterface::encryptAsOutsider},
        {DecryptFromOutsider, &GroupApiVarInterface::decryptFromOutsider},
        {DecryptAnonymous, &GroupApiVarInterface::decryptAnonymous},
        {DecryptShared, &GroupApiVarInterface::decryptShared},
        {PeekEnvelope, &GroupApiVarInterface::peekEnvelope},
        {NoLocation, &GroupApiVarInterface::noLocation},
        {IdFromString, &GroupApiVarInterface::idFromString},
        {DeriveGroupId, &GroupApiVarInterface::deriveGroupId},
        {GetGroups, &GroupApiVarInterface::getGroups},
        {GetGroupPublicKey, &GroupApiVarInterface::getGroupPublicKey},
        {SetGroupVisibility, &GroupApiVarInterface::setGroupVisibility},
        {ReplaceGroupMemberKeys, &GroupApiVarInterface::replaceGroupMemberKeys},
        {SetGroupRoles, &GroupApiVarInterface::setGroupRoles},
        {UpdateGroupRules, &GroupApiVarInterface::updateGroupRules},
        {GetGroupLog, &GroupApiVarInterface::getGroupLog},
        {BeginFileEncryptionAsOutsider, &GroupApiVarInterface::beginFileEncryptionAsOutsider},
        {BeginFileDecryptionFromOutsider, &GroupApiVarInterface::beginFileDecryptionFromOutsider},
        {BeginAnonymousFileDecryption, &GroupApiVarInterface::beginAnonymousFileDecryption},
        {BeginSharedFileDecryption, &GroupApiVarInterface::beginSharedFileDecryption},
        {GetFileCipherRange, &GroupApiVarInterface::getFileCipherRange},
        {BeginSequence, &GroupApiVarInterface::beginSequence},
        {GetSequenceHeader, &GroupApiVarInterface::getSequenceHeader},
        {AppendToSequence, &GroupApiVarInterface::appendToSequence},
        {CheckpointSequence, &GroupApiVarInterface::checkpointSequence},
        {FinishSequence, &GroupApiVarInterface::finishSequence},
        {OpenSequence, &GroupApiVarInterface::openSequence},
        {ReadSequenceItem, &GroupApiVarInterface::readSequenceItem},
        {VerifySequenceMark, &GroupApiVarInterface::verifySequenceMark},
        {CloseSequence, &GroupApiVarInterface::closeSequence},
        {PeekSequenceItem, &GroupApiVarInterface::peekSequenceItem},
        {CreateSpace, &GroupApiVarInterface::createSpace},
        {DeriveSpaceId, &GroupApiVarInterface::deriveSpaceId},
        {GetSpace, &GroupApiVarInterface::getSpace},
        {ListSpaces, &GroupApiVarInterface::listSpaces},
        {DeleteSpace, &GroupApiVarInterface::deleteSpace},
        {AddSpaceRecipients, &GroupApiVarInterface::addSpaceRecipients},
        {RemoveSpaceRecipients, &GroupApiVarInterface::removeSpaceRecipients},
        {RotateSpaceKey, &GroupApiVarInterface::rotateSpaceKey},
        {UpdateSpacePublicMeta, &GroupApiVarInterface::updateSpacePublicMeta},
        {UpdateSpacePrivateMeta, &GroupApiVarInterface::updateSpacePrivateMeta},
        {EncryptInSpace, &GroupApiVarInterface::encryptInSpace},
        {DecryptInSpace, &GroupApiVarInterface::decryptInSpace},
        {DecryptManyInSpace, &GroupApiVarInterface::decryptManyInSpace},
        {BeginFileEncryptionInSpace, &GroupApiVarInterface::beginFileEncryptionInSpace},
        {BeginFileDecryptionInSpace, &GroupApiVarInterface::beginFileDecryptionInSpace},
        {BeginSequenceInSpace, &GroupApiVarInterface::beginSequenceInSpace},
        {OpenSequenceInSpace, &GroupApiVarInterface::openSequenceInSpace},
        {GetSpaceSequenceOrigin, &GroupApiVarInterface::getSpaceSequenceOrigin},
        {EncodePath, &GroupApiVarInterface::encodePath},
        {PinGroupToSubject, &GroupApiVarInterface::pinGroupToSubject},
        {GetSpaceLog, &GroupApiVarInterface::getSpaceLog},
        {AbortFile, &GroupApiVarInterface::abortFile}
};

Poco::Dynamic::Var GroupApiVarInterface::create(const Poco::Dynamic::Var& args) {
    core::VarInterfaceUtil::validateAndExtractArray(args, 0);
    _groupApi = GroupApi::create(_connection);
    return {};
}

Poco::Dynamic::Var GroupApiVarInterface::createGroup(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 6, 8);
    auto contextId = _deserializer.deserialize<std::string>(argsArr->get(0), "contextId");
    auto users = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(1), "users");
    auto managers = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(2), "managers");
    auto publicMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(3), "publicMeta");
    auto privateMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(4), "privateMeta");
    auto rules = _deserializer.deserializeOptional<GroupRulesUpdate>(argsArr->get(5), "rules");
    auto idSeed = argsArr->size() > 6 ? _deserializer.deserializeOptional<core::Buffer>(argsArr->get(6), "idSeed") :
                                        std::optional<core::Buffer>();
    auto visibleTo = argsArr->size() > 7 ?
        _deserializer.deserializeOptional<std::string>(argsArr->get(7), "visibleTo").value_or("members") :
        std::string("members");
    auto result = _groupApi.createGroup(contextId, users, managers, publicMeta, privateMeta, rules, idSeed, visibleTo);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var GroupApiVarInterface::addGroupMembers(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto groupId = _deserializer.deserialize<std::string>(argsArr->get(0), "groupId");
    auto newMembers = _deserializer.deserializeVector<GroupMemberToAdd>(argsArr->get(1), "newMembers");
    _groupApi.addGroupMembers(groupId, newMembers);
    return {};
}

Poco::Dynamic::Var GroupApiVarInterface::removeGroupMembers(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto groupId = _deserializer.deserialize<std::string>(argsArr->get(0), "groupId");
    auto userIds = _deserializer.deserializeVector<std::string>(argsArr->get(1), "userIds");
    auto result = _groupApi.removeGroupMembers(groupId, userIds);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var GroupApiVarInterface::rotateGroupKey(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto groupId = _deserializer.deserialize<std::string>(argsArr->get(0), "groupId");
    auto result = _groupApi.rotateGroupKey(groupId);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var GroupApiVarInterface::renewLeaf(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto groupId = _deserializer.deserialize<std::string>(argsArr->get(0), "groupId");
    auto previousUserPrivKey = _deserializer.deserialize<std::string>(argsArr->get(1), "previousUserPrivKey");
    return _serializer.serialize(_groupApi.renewLeaf(groupId, previousUserPrivKey));
}

Poco::Dynamic::Var GroupApiVarInterface::updateGroupPublicMeta(const Poco::Dynamic::Var& args) {
    // One plane per call, and no roster: seating a member re-keys their path, so membership goes through
    // addGroupMembers / removeGroupMembers, and each metadata plane has an RPC and a permission of its own.
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 3);
    auto groupId = _deserializer.deserialize<std::string>(argsArr->get(0), "groupId");
    auto publicMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(1), "publicMeta");
    auto version = _deserializer.deserialize<int64_t>(argsArr->get(2), "version");
    _groupApi.updateGroupPublicMeta(groupId, publicMeta, version);
    return {};
}

Poco::Dynamic::Var GroupApiVarInterface::updateGroupPrivateMeta(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 3);
    auto groupId = _deserializer.deserialize<std::string>(argsArr->get(0), "groupId");
    auto privateMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(1), "privateMeta");
    auto version = _deserializer.deserialize<int64_t>(argsArr->get(2), "version");
    _groupApi.updateGroupPrivateMeta(groupId, privateMeta, version);
    return {};
}

Poco::Dynamic::Var GroupApiVarInterface::deleteGroup(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto groupId = _deserializer.deserialize<std::string>(argsArr->get(0), "groupId");
    _groupApi.deleteGroup(groupId);
    return {};
}

Poco::Dynamic::Var GroupApiVarInterface::getGroup(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto groupId = _deserializer.deserialize<std::string>(argsArr->get(0), "groupId");
    auto result = _groupApi.getGroup(groupId);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var GroupApiVarInterface::listGroups(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto contextId = _deserializer.deserialize<std::string>(argsArr->get(0), "contextId");
    auto pagingQuery = _deserializer.deserialize<core::PagingQuery>(argsArr->get(1), "pagingQuery");
    auto result = _groupApi.listGroups(contextId, pagingQuery);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var GroupApiVarInterface::subscribeFor(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto subscriptionQueries = _deserializer.deserializeVector<std::string>(argsArr->get(0), "subscriptionQueries");
    auto result = _groupApi.subscribeFor(subscriptionQueries);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var GroupApiVarInterface::unsubscribeFrom(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto subscriptionIds = _deserializer.deserializeVector<std::string>(argsArr->get(0), "subscriptionIds");
    _groupApi.unsubscribeFrom(subscriptionIds);
    return {};
}

Poco::Dynamic::Var GroupApiVarInterface::buildSubscriptionQuery(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 3);
    auto eventType = _deserializer.deserialize<group::EventType>(argsArr->get(0), "eventType");
    auto selectorType = _deserializer.deserialize<group::EventSelectorType>(argsArr->get(1), "selectorType");
    auto selectorId = _deserializer.deserialize<std::string>(argsArr->get(2), "selectorId");
    auto result = _groupApi.buildSubscriptionQuery(eventType, selectorType, selectorId);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var GroupApiVarInterface::encrypt(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 3, 4);
    auto groupId = _deserializer.deserialize<std::string>(argsArr->get(0), "groupId");
    auto location = _deserializer.deserializeVector<PathSegment>(argsArr->get(1), "location");
    auto content = _deserializer.deserialize<core::Buffer>(argsArr->get(2), "content");
    auto options = argsArr->size() > 3 ? _deserializer.deserialize<EncryptOptions>(argsArr->get(3), "options") :
                                         EncryptOptions{};
    auto result = _groupApi.encrypt(groupId, location, content, options);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var GroupApiVarInterface::decrypt(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 4);
    auto groupId = _deserializer.deserialize<std::string>(argsArr->get(0), "groupId");
    auto location = _deserializer.deserializeVector<PathSegment>(argsArr->get(1), "location");
    auto envelope = _deserializer.deserialize<core::Buffer>(argsArr->get(2), "envelope");
    auto options = _deserializer.deserialize<DecryptOptions>(argsArr->get(3), "options");
    auto result = _groupApi.decrypt(groupId, location, envelope, options);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var GroupApiVarInterface::decryptMany(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto groupId = _deserializer.deserialize<std::string>(argsArr->get(0), "groupId");
    auto items = _deserializer.deserializeVector<DecryptItem>(argsArr->get(1), "items");
    auto result = _groupApi.decryptMany(groupId, items);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var GroupApiVarInterface::encryptAsOutsider(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 4, 5);
    auto contextId = _deserializer.deserialize<std::string>(argsArr->get(0), "contextId");
    auto groupId = _deserializer.deserialize<std::string>(argsArr->get(1), "groupId");
    auto location = _deserializer.deserializeVector<PathSegment>(argsArr->get(2), "location");
    auto content = _deserializer.deserialize<core::Buffer>(argsArr->get(3), "content");
    auto options = argsArr->size() > 4 ? _deserializer.deserialize<EncryptOptions>(argsArr->get(4), "options") :
                                         EncryptOptions{};
    auto result = _groupApi.encryptAsOutsider(contextId, groupId, location, content, options);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var GroupApiVarInterface::encryptAnonymously(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 4);
    auto groupId = _deserializer.deserialize<std::string>(argsArr->get(0), "groupId");
    auto groupPubKey = _deserializer.deserialize<std::string>(argsArr->get(1), "groupPubKey");
    auto location = _deserializer.deserializeVector<PathSegment>(argsArr->get(2), "location");
    auto content = _deserializer.deserialize<core::Buffer>(argsArr->get(3), "content");
    auto result = _groupApi.encryptAnonymously(groupId, groupPubKey, location, content);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var GroupApiVarInterface::decryptFromOutsider(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 4);
    auto groupId = _deserializer.deserialize<std::string>(argsArr->get(0), "groupId");
    auto location = _deserializer.deserializeVector<PathSegment>(argsArr->get(1), "location");
    auto envelope = _deserializer.deserialize<core::Buffer>(argsArr->get(2), "envelope");
    auto options = _deserializer.deserialize<DecryptOptions>(argsArr->get(3), "options");
    auto result = _groupApi.decryptFromOutsider(groupId, location, envelope, options);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var GroupApiVarInterface::decryptAnonymous(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 3);
    auto groupId = _deserializer.deserialize<std::string>(argsArr->get(0), "groupId");
    auto location = _deserializer.deserializeVector<PathSegment>(argsArr->get(1), "location");
    auto envelope = _deserializer.deserialize<core::Buffer>(argsArr->get(2), "envelope");
    auto result = _groupApi.decryptAnonymous(groupId, location, envelope);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var GroupApiVarInterface::decryptShared(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 4);
    auto contextId = _deserializer.deserialize<std::string>(argsArr->get(0), "contextId");
    auto location = _deserializer.deserializeVector<PathSegment>(argsArr->get(1), "location");
    auto envelope = _deserializer.deserialize<core::Buffer>(argsArr->get(2), "envelope");
    auto options = _deserializer.deserialize<DecryptOptions>(argsArr->get(3), "options");
    auto result = _groupApi.decryptShared(contextId, location, envelope, options);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var GroupApiVarInterface::peekEnvelope(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto envelope = _deserializer.deserialize<core::Buffer>(argsArr->get(0), "envelope");
    auto result = GroupApi::peekEnvelope(envelope);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var GroupApiVarInterface::noLocation(const Poco::Dynamic::Var& args) {
    core::VarInterfaceUtil::validateAndExtractArray(args, 0);
    auto result = GroupApi::noLocation();
    return _serializer.serialize(result);
}

Poco::Dynamic::Var GroupApiVarInterface::idFromString(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto identifier = _deserializer.deserialize<std::string>(argsArr->get(0), "identifier");
    auto result = GroupApi::idFromString(identifier);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var GroupApiVarInterface::beginFileEncryption(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 3);
    auto groupId = _deserializer.deserialize<std::string>(argsArr->get(0), "groupId");
    auto location = _deserializer.deserializeVector<PathSegment>(argsArr->get(1), "location");
    auto options = _deserializer.deserialize<EncryptOptions>(argsArr->get(2), "options");
    return _serializer.serialize(_groupApi.beginFileEncryption(groupId, location, options));
}

Poco::Dynamic::Var GroupApiVarInterface::encryptFileChunk(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto fileHandle = _deserializer.deserialize<int64_t>(argsArr->get(0), "fileHandle");
    auto plainChunk = _deserializer.deserialize<core::Buffer>(argsArr->get(1), "plainChunk");
    auto result = _groupApi.encryptFileChunk(fileHandle, plainChunk);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var GroupApiVarInterface::beginFileDecryption(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 4);
    auto groupId = _deserializer.deserialize<std::string>(argsArr->get(0), "groupId");
    auto location = _deserializer.deserializeVector<PathSegment>(argsArr->get(1), "location");
    auto envelope = _deserializer.deserialize<core::Buffer>(argsArr->get(2), "envelope");
    auto options = _deserializer.deserialize<DecryptOptions>(argsArr->get(3), "options");
    return _serializer.serialize(_groupApi.beginFileDecryption(groupId, location, envelope, options));
}

Poco::Dynamic::Var GroupApiVarInterface::decryptFileChunk(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto fileHandle = _deserializer.deserialize<int64_t>(argsArr->get(0), "fileHandle");
    auto cipherChunk = _deserializer.deserialize<core::Buffer>(argsArr->get(1), "cipherChunk");
    auto result = _groupApi.decryptFileChunk(fileHandle, cipherChunk);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var GroupApiVarInterface::finishFileEncryption(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto fileHandle = _deserializer.deserialize<int64_t>(argsArr->get(0), "fileHandle");
    auto result = _groupApi.finishFileEncryption(fileHandle);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var GroupApiVarInterface::finishFileDecryption(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto fileHandle = _deserializer.deserialize<int64_t>(argsArr->get(0), "fileHandle");
    auto result = _groupApi.finishFileDecryption(fileHandle);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var GroupApiVarInterface::beginFileEncryptionAnonymously(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 3);
    auto groupId = _deserializer.deserialize<std::string>(argsArr->get(0), "groupId");
    auto groupPubKey = _deserializer.deserialize<std::string>(argsArr->get(1), "groupPubKey");
    auto location = _deserializer.deserializeVector<PathSegment>(argsArr->get(2), "location");
    return _serializer.serialize(_groupApi.beginFileEncryptionAnonymously(groupId, groupPubKey, location));
}

Poco::Dynamic::Var GroupApiVarInterface::seekInEncryptedFile(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto fileHandle = _deserializer.deserialize<int64_t>(argsArr->get(0), "fileHandle");
    auto position = _deserializer.deserialize<int64_t>(argsArr->get(1), "position");
    auto result = _groupApi.seekInEncryptedFile(fileHandle, position);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var GroupApiVarInterface::sendCustomEvent(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 4);
    auto groupId = _deserializer.deserialize<std::string>(argsArr->get(0), "groupId");
    auto channelName = _deserializer.deserialize<std::string>(argsArr->get(1), "channelName");
    auto eventData = _deserializer.deserialize<core::Buffer>(argsArr->get(2), "eventData");
    auto users = _deserializer.deserializeVector<std::string>(argsArr->get(3), "users");
    _groupApi.sendCustomEvent(groupId, channelName, eventData, users);
    return {};
}

Poco::Dynamic::Var GroupApiVarInterface::buildCustomEventSubscriptionQuery(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 3);
    auto channelName = _deserializer.deserialize<std::string>(argsArr->get(0), "channelName");
    auto selectorType = _deserializer.deserialize<group::EventSelectorType>(argsArr->get(1), "selectorType");
    auto selectorId = _deserializer.deserialize<std::string>(argsArr->get(2), "selectorId");
    auto result = _groupApi.buildCustomEventSubscriptionQuery(channelName, selectorType, selectorId);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var GroupApiVarInterface::exec(METHOD method, const Poco::Dynamic::Var& args) {
    auto it = methodMap.find(method);
    if (it == methodMap.end()) {
        throw core::InvalidMethodException("method=" + std::to_string((int64_t)method));
    }
    return (*this.*(it->second))(args);
}

Poco::Dynamic::Var GroupApiVarInterface::deriveGroupId(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto contextId = _deserializer.deserialize<std::string>(argsArr->get(0), "contextId");
    auto idSeed = _deserializer.deserialize<core::Buffer>(argsArr->get(1), "idSeed");
    auto result = GroupApi::deriveGroupId(contextId, idSeed);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var GroupApiVarInterface::getGroups(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto groupIds = _deserializer.deserializeVector<std::string>(argsArr->get(0), "groupIds");
    auto result = _groupApi.getGroups(groupIds);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var GroupApiVarInterface::getGroupPublicKey(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto contextId = _deserializer.deserialize<std::string>(argsArr->get(0), "contextId");
    auto groupId = _deserializer.deserialize<std::string>(argsArr->get(1), "groupId");
    auto result = _groupApi.getGroupPublicKey(contextId, groupId);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var GroupApiVarInterface::setGroupVisibility(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto groupId = _deserializer.deserialize<std::string>(argsArr->get(0), "groupId");
    auto visibleTo = _deserializer.deserialize<std::string>(argsArr->get(1), "visibleTo");
    _groupApi.setGroupVisibility(groupId, visibleTo);
    return {};
}

Poco::Dynamic::Var GroupApiVarInterface::replaceGroupMemberKeys(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto groupId = _deserializer.deserialize<std::string>(argsArr->get(0), "groupId");
    auto userIds = _deserializer.deserializeVector<std::string>(argsArr->get(1), "userIds");
    return _serializer.serialize(_groupApi.replaceGroupMemberKeys(groupId, userIds));
}

Poco::Dynamic::Var GroupApiVarInterface::setGroupRoles(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto groupId = _deserializer.deserialize<std::string>(argsArr->get(0), "groupId");
    auto changes = _deserializer.deserializeVector<GroupRoleChange>(argsArr->get(1), "changes");
    _groupApi.setGroupRoles(groupId, changes);
    return {};
}

Poco::Dynamic::Var GroupApiVarInterface::updateGroupRules(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto groupId = _deserializer.deserialize<std::string>(argsArr->get(0), "groupId");
    auto rules = _deserializer.deserialize<GroupRulesUpdate>(argsArr->get(1), "rules");
    _groupApi.updateGroupRules(groupId, rules);
    return {};
}

Poco::Dynamic::Var GroupApiVarInterface::getGroupLog(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto groupId = _deserializer.deserialize<std::string>(argsArr->get(0), "groupId");
    auto pagingQuery = _deserializer.deserialize<core::PagingQuery>(argsArr->get(1), "pagingQuery");
    return _serializer.serialize(_groupApi.getGroupLog(groupId, pagingQuery));
}

Poco::Dynamic::Var GroupApiVarInterface::beginFileEncryptionAsOutsider(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 4);
    auto contextId = _deserializer.deserialize<std::string>(argsArr->get(0), "contextId");
    auto groupId = _deserializer.deserialize<std::string>(argsArr->get(1), "groupId");
    auto location = _deserializer.deserializeVector<PathSegment>(argsArr->get(2), "location");
    auto options = _deserializer.deserialize<EncryptOptions>(argsArr->get(3), "options");
    return _serializer.serialize(_groupApi.beginFileEncryptionAsOutsider(contextId, groupId, location, options));
}

Poco::Dynamic::Var GroupApiVarInterface::beginFileDecryptionFromOutsider(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 4);
    auto groupId = _deserializer.deserialize<std::string>(argsArr->get(0), "groupId");
    auto location = _deserializer.deserializeVector<PathSegment>(argsArr->get(1), "location");
    auto envelope = _deserializer.deserialize<core::Buffer>(argsArr->get(2), "envelope");
    auto options = _deserializer.deserialize<DecryptOptions>(argsArr->get(3), "options");
    return _serializer.serialize(_groupApi.beginFileDecryptionFromOutsider(groupId, location, envelope, options));
}

Poco::Dynamic::Var GroupApiVarInterface::beginAnonymousFileDecryption(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 3);
    auto groupId = _deserializer.deserialize<std::string>(argsArr->get(0), "groupId");
    auto location = _deserializer.deserializeVector<PathSegment>(argsArr->get(1), "location");
    auto envelope = _deserializer.deserialize<core::Buffer>(argsArr->get(2), "envelope");
    return _serializer.serialize(_groupApi.beginAnonymousFileDecryption(groupId, location, envelope));
}

Poco::Dynamic::Var GroupApiVarInterface::beginSharedFileDecryption(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 4);
    auto contextId = _deserializer.deserialize<std::string>(argsArr->get(0), "contextId");
    auto location = _deserializer.deserializeVector<PathSegment>(argsArr->get(1), "location");
    auto envelope = _deserializer.deserialize<core::Buffer>(argsArr->get(2), "envelope");
    auto options = _deserializer.deserialize<DecryptOptions>(argsArr->get(3), "options");
    return _serializer.serialize(_groupApi.beginSharedFileDecryption(contextId, location, envelope, options));
}

Poco::Dynamic::Var GroupApiVarInterface::getFileCipherRange(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 3);
    auto fileHandle = _deserializer.deserialize<int64_t>(argsArr->get(0), "fileHandle");
    auto from = _deserializer.deserialize<int64_t>(argsArr->get(1), "from");
    auto to = _deserializer.deserialize<int64_t>(argsArr->get(2), "to");
    return _serializer.serialize(_groupApi.getFileCipherRange(fileHandle, from, to));
}

Poco::Dynamic::Var GroupApiVarInterface::beginSequence(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 3);
    auto groupId = _deserializer.deserialize<std::string>(argsArr->get(0), "groupId");
    auto location = _deserializer.deserializeVector<PathSegment>(argsArr->get(1), "location");
    auto checkpointEvery = _deserializer.deserialize<int64_t>(argsArr->get(2), "checkpointEvery");
    return _serializer.serialize(_groupApi.beginSequence(groupId, location, checkpointEvery));
}

Poco::Dynamic::Var GroupApiVarInterface::getSequenceHeader(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto sequence = _deserializer.deserialize<int64_t>(argsArr->get(0), "sequence");
    return _serializer.serialize(_groupApi.getSequenceHeader(sequence));
}

Poco::Dynamic::Var GroupApiVarInterface::appendToSequence(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto sequence = _deserializer.deserialize<int64_t>(argsArr->get(0), "sequence");
    auto data = _deserializer.deserialize<core::Buffer>(argsArr->get(1), "data");
    return _serializer.serialize(_groupApi.appendToSequence(sequence, data));
}

Poco::Dynamic::Var GroupApiVarInterface::checkpointSequence(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto sequence = _deserializer.deserialize<int64_t>(argsArr->get(0), "sequence");
    return _serializer.serialize(_groupApi.checkpointSequence(sequence));
}

Poco::Dynamic::Var GroupApiVarInterface::finishSequence(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto sequence = _deserializer.deserialize<int64_t>(argsArr->get(0), "sequence");
    return _serializer.serialize(_groupApi.finishSequence(sequence));
}

Poco::Dynamic::Var GroupApiVarInterface::openSequence(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 4, 5);
    auto groupId = _deserializer.deserialize<std::string>(argsArr->get(0), "groupId");
    auto location = _deserializer.deserializeVector<PathSegment>(argsArr->get(1), "location");
    auto header = _deserializer.deserialize<core::Buffer>(argsArr->get(2), "header");
    auto options = _deserializer.deserialize<DecryptOptions>(argsArr->get(3), "options");
    auto resumeFrom = argsArr->size() > 4 && !argsArr->get(4).isEmpty() ?
        std::optional<core::Buffer>(_deserializer.deserialize<core::Buffer>(argsArr->get(4), "resumeFrom")) :
        std::optional<core::Buffer>();
    return _serializer.serialize(_groupApi.openSequence(groupId, location, header, options, resumeFrom));
}

Poco::Dynamic::Var GroupApiVarInterface::readSequenceItem(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto sequence = _deserializer.deserialize<int64_t>(argsArr->get(0), "sequence");
    auto item = _deserializer.deserialize<core::Buffer>(argsArr->get(1), "item");
    return _serializer.serialize(_groupApi.readSequenceItem(sequence, item));
}

Poco::Dynamic::Var GroupApiVarInterface::verifySequenceMark(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto sequence = _deserializer.deserialize<int64_t>(argsArr->get(0), "sequence");
    auto mark = _deserializer.deserialize<core::Buffer>(argsArr->get(1), "mark");
    return _serializer.serialize(_groupApi.verifySequenceMark(sequence, mark));
}

Poco::Dynamic::Var GroupApiVarInterface::closeSequence(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto sequence = _deserializer.deserialize<int64_t>(argsArr->get(0), "sequence");
    _groupApi.closeSequence(sequence);
    return {};
}

Poco::Dynamic::Var GroupApiVarInterface::peekSequenceItem(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto itemOrMark = _deserializer.deserialize<core::Buffer>(argsArr->get(0), "itemOrMark");
    return _serializer.serialize(GroupApi::peekSequenceItem(itemOrMark));
}

Poco::Dynamic::Var GroupApiVarInterface::createSpace(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 4, 5);
    auto contextId = _deserializer.deserialize<std::string>(argsArr->get(0), "contextId");
    auto recipients = _deserializer.deserializeVector<SpaceRecipient>(argsArr->get(1), "recipients");
    auto publicMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(2), "publicMeta");
    auto privateMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(3), "privateMeta");
    auto idSeed = argsArr->size() > 4 && !argsArr->get(4).isEmpty() ?
        std::optional<core::Buffer>(_deserializer.deserialize<core::Buffer>(argsArr->get(4), "idSeed")) :
        std::optional<core::Buffer>();
    return _serializer.serialize(_groupApi.createSpace(contextId, recipients, publicMeta, privateMeta, idSeed));
}

Poco::Dynamic::Var GroupApiVarInterface::deriveSpaceId(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto contextId = _deserializer.deserialize<std::string>(argsArr->get(0), "contextId");
    auto idSeed = _deserializer.deserialize<core::Buffer>(argsArr->get(1), "idSeed");
    return _serializer.serialize(GroupApi::deriveSpaceId(contextId, idSeed));
}

Poco::Dynamic::Var GroupApiVarInterface::getSpace(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto spaceId = _deserializer.deserialize<std::string>(argsArr->get(0), "spaceId");
    return _serializer.serialize(_groupApi.getSpace(spaceId));
}

Poco::Dynamic::Var GroupApiVarInterface::listSpaces(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto contextId = _deserializer.deserialize<std::string>(argsArr->get(0), "contextId");
    auto pagingQuery = _deserializer.deserialize<core::PagingQuery>(argsArr->get(1), "pagingQuery");
    return _serializer.serialize(_groupApi.listSpaces(contextId, pagingQuery));
}

Poco::Dynamic::Var GroupApiVarInterface::deleteSpace(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto spaceId = _deserializer.deserialize<std::string>(argsArr->get(0), "spaceId");
    _groupApi.deleteSpace(spaceId);
    return {};
}

Poco::Dynamic::Var GroupApiVarInterface::addSpaceRecipients(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto spaceId = _deserializer.deserialize<std::string>(argsArr->get(0), "spaceId");
    auto recipients = _deserializer.deserializeVector<SpaceRecipient>(argsArr->get(1), "recipients");
    _groupApi.addSpaceRecipients(spaceId, recipients);
    return {};
}

Poco::Dynamic::Var GroupApiVarInterface::removeSpaceRecipients(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto spaceId = _deserializer.deserialize<std::string>(argsArr->get(0), "spaceId");
    auto recipients = _deserializer.deserializeVector<SpaceRecipientRef>(argsArr->get(1), "recipients");
    return _serializer.serialize(_groupApi.removeSpaceRecipients(spaceId, recipients));
}

Poco::Dynamic::Var GroupApiVarInterface::rotateSpaceKey(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto spaceId = _deserializer.deserialize<std::string>(argsArr->get(0), "spaceId");
    return _serializer.serialize(_groupApi.rotateSpaceKey(spaceId));
}

Poco::Dynamic::Var GroupApiVarInterface::updateSpacePublicMeta(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 3);
    auto spaceId = _deserializer.deserialize<std::string>(argsArr->get(0), "spaceId");
    auto meta = _deserializer.deserialize<core::Buffer>(argsArr->get(1), "meta");
    auto version = _deserializer.deserialize<int64_t>(argsArr->get(2), "version");
    _groupApi.updateSpacePublicMeta(spaceId, meta, version);
    return {};
}

Poco::Dynamic::Var GroupApiVarInterface::updateSpacePrivateMeta(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 3);
    auto spaceId = _deserializer.deserialize<std::string>(argsArr->get(0), "spaceId");
    auto meta = _deserializer.deserialize<core::Buffer>(argsArr->get(1), "meta");
    auto version = _deserializer.deserialize<int64_t>(argsArr->get(2), "version");
    _groupApi.updateSpacePrivateMeta(spaceId, meta, version);
    return {};
}

Poco::Dynamic::Var GroupApiVarInterface::encryptInSpace(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 3);
    auto spaceId = _deserializer.deserialize<std::string>(argsArr->get(0), "spaceId");
    auto location = _deserializer.deserializeVector<PathSegment>(argsArr->get(1), "location");
    auto data = _deserializer.deserialize<core::Buffer>(argsArr->get(2), "data");
    return _serializer.serialize(_groupApi.encryptInSpace(spaceId, location, data));
}

Poco::Dynamic::Var GroupApiVarInterface::decryptInSpace(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 4);
    auto spaceId = _deserializer.deserialize<std::string>(argsArr->get(0), "spaceId");
    auto location = _deserializer.deserializeVector<PathSegment>(argsArr->get(1), "location");
    auto envelope = _deserializer.deserialize<core::Buffer>(argsArr->get(2), "envelope");
    auto options = _deserializer.deserialize<DecryptOptions>(argsArr->get(3), "options");
    return _serializer.serialize(_groupApi.decryptInSpace(spaceId, location, envelope, options));
}

Poco::Dynamic::Var GroupApiVarInterface::decryptManyInSpace(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto spaceId = _deserializer.deserialize<std::string>(argsArr->get(0), "spaceId");
    auto items = _deserializer.deserializeVector<DecryptItem>(argsArr->get(1), "items");
    return _serializer.serialize(_groupApi.decryptManyInSpace(spaceId, items));
}

Poco::Dynamic::Var GroupApiVarInterface::beginFileEncryptionInSpace(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto spaceId = _deserializer.deserialize<std::string>(argsArr->get(0), "spaceId");
    auto location = _deserializer.deserializeVector<PathSegment>(argsArr->get(1), "location");
    return _serializer.serialize(_groupApi.beginFileEncryptionInSpace(spaceId, location));
}

Poco::Dynamic::Var GroupApiVarInterface::beginFileDecryptionInSpace(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 4);
    auto spaceId = _deserializer.deserialize<std::string>(argsArr->get(0), "spaceId");
    auto location = _deserializer.deserializeVector<PathSegment>(argsArr->get(1), "location");
    auto envelope = _deserializer.deserialize<core::Buffer>(argsArr->get(2), "envelope");
    auto options = _deserializer.deserialize<DecryptOptions>(argsArr->get(3), "options");
    return _serializer.serialize(_groupApi.beginFileDecryptionInSpace(spaceId, location, envelope, options));
}

Poco::Dynamic::Var GroupApiVarInterface::beginSequenceInSpace(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 3);
    auto spaceId = _deserializer.deserialize<std::string>(argsArr->get(0), "spaceId");
    auto location = _deserializer.deserializeVector<PathSegment>(argsArr->get(1), "location");
    auto checkpointEvery = _deserializer.deserialize<int64_t>(argsArr->get(2), "checkpointEvery");
    return _serializer.serialize(_groupApi.beginSequenceInSpace(spaceId, location, checkpointEvery));
}

Poco::Dynamic::Var GroupApiVarInterface::openSequenceInSpace(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 4, 5);
    auto spaceId = _deserializer.deserialize<std::string>(argsArr->get(0), "spaceId");
    auto location = _deserializer.deserializeVector<PathSegment>(argsArr->get(1), "location");
    auto header = _deserializer.deserialize<core::Buffer>(argsArr->get(2), "header");
    auto options = _deserializer.deserialize<DecryptOptions>(argsArr->get(3), "options");
    auto resumeFrom = argsArr->size() > 4 && !argsArr->get(4).isEmpty() ?
        std::optional<core::Buffer>(_deserializer.deserialize<core::Buffer>(argsArr->get(4), "resumeFrom")) :
        std::optional<core::Buffer>();
    return _serializer.serialize(_groupApi.openSequenceInSpace(spaceId, location, header, options, resumeFrom));
}

Poco::Dynamic::Var GroupApiVarInterface::getSpaceSequenceOrigin(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto sequence = _deserializer.deserialize<int64_t>(argsArr->get(0), "sequence");
    return _serializer.serialize(_groupApi.getSpaceSequenceOrigin(sequence));
}

Poco::Dynamic::Var GroupApiVarInterface::encodePath(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto path = _deserializer.deserializeVector<PathSegment>(argsArr->get(0), "path");
    return _serializer.serialize(GroupApi::encodePath(path));
}

Poco::Dynamic::Var GroupApiVarInterface::pinGroupToSubject(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 3);
    auto contextId = _deserializer.deserialize<std::string>(argsArr->get(0), "contextId");
    auto subject = _deserializer.deserializeVector<PathSegment>(argsArr->get(1), "subject");
    auto groupId = _deserializer.deserialize<std::string>(argsArr->get(2), "groupId");
    _groupApi.pinGroupToSubject(contextId, subject, groupId);
    return {};
}

Poco::Dynamic::Var GroupApiVarInterface::getSpaceLog(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto spaceId = _deserializer.deserialize<std::string>(argsArr->get(0), "spaceId");
    auto pagingQuery = _deserializer.deserialize<core::PagingQuery>(argsArr->get(1), "pagingQuery");
    return _serializer.serialize(_groupApi.getSpaceLog(spaceId, pagingQuery));
}

Poco::Dynamic::Var GroupApiVarInterface::abortFile(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto fileHandle = _deserializer.deserialize<int64_t>(argsArr->get(0), "fileHandle");
    _groupApi.abortFile(fileHandle);
    return {};
}
