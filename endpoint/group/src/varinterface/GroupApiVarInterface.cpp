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
        {UpdateGroupPolicy, &GroupApiVarInterface::updateGroupPolicy},
        {RotateGroupKey, &GroupApiVarInterface::rotateGroupKey},
        {RenewLeaf, &GroupApiVarInterface::renewLeaf},
        {DecryptMany, &GroupApiVarInterface::decryptMany},
        {EncryptAsOutsider, &GroupApiVarInterface::encryptAsOutsider},
        {DecryptFromOutsider, &GroupApiVarInterface::decryptFromOutsider},
        {DecryptAnonymous, &GroupApiVarInterface::decryptAnonymous},
        {DecryptShared, &GroupApiVarInterface::decryptShared},
        {PeekEnvelope, &GroupApiVarInterface::peekEnvelope},
        {NoLocation, &GroupApiVarInterface::noLocation},
        {IdFromString, &GroupApiVarInterface::idFromString}
};

Poco::Dynamic::Var GroupApiVarInterface::create(const Poco::Dynamic::Var& args) {
    core::VarInterfaceUtil::validateAndExtractArray(args, 0);
    _groupApi = GroupApi::create(_connection);
    return {};
}

Poco::Dynamic::Var GroupApiVarInterface::createGroup(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 6);
    auto contextId = _deserializer.deserialize<std::string>(argsArr->get(0), "contextId");
    auto users = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(1), "users");
    auto managers = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(2), "managers");
    auto publicMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(3), "publicMeta");
    auto privateMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(4), "privateMeta");
    auto policies = _deserializer.deserializeOptional<core::ContainerPolicy>(argsArr->get(5), "policies");
    auto result = _groupApi.createGroup(contextId, users, managers, publicMeta, privateMeta, policies);
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
    _groupApi.removeGroupMembers(groupId, userIds);
    return {};
}

Poco::Dynamic::Var GroupApiVarInterface::rotateGroupKey(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto groupId = _deserializer.deserialize<std::string>(argsArr->get(0), "groupId");
    _groupApi.rotateGroupKey(groupId);
    return {};
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

Poco::Dynamic::Var GroupApiVarInterface::updateGroupPolicy(const Poco::Dynamic::Var& args) {
    // Required, not optional: on a call that does nothing else, an absent policy is a request that asks for
    // nothing — where on the old combined call it meant "leave the policy alone".
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto groupId = _deserializer.deserialize<std::string>(argsArr->get(0), "groupId");
    auto policies = _deserializer.deserialize<core::ContainerPolicy>(argsArr->get(1), "policies");
    _groupApi.updateGroupPolicy(groupId, policies);
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
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto groupId = _deserializer.deserialize<std::string>(argsArr->get(0), "groupId");
    auto size = _deserializer.deserialize<int64_t>(argsArr->get(1), "size");
    auto result = _groupApi.beginFileEncryption(groupId, size);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var GroupApiVarInterface::encryptFileChunk(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto fileHandle = _deserializer.deserialize<int64_t>(argsArr->get(0), "fileHandle");
    auto plainChunk = _deserializer.deserialize<core::Buffer>(argsArr->get(1), "plainChunk");
    auto result = _groupApi.encryptFileChunk(fileHandle, plainChunk);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var GroupApiVarInterface::beginFileDecryption(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto envelope = _deserializer.deserialize<core::Buffer>(argsArr->get(0), "envelope");
    auto result = _groupApi.beginFileDecryption(envelope);
    return _serializer.serialize(result);
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
    auto size = _deserializer.deserialize<int64_t>(argsArr->get(2), "size");
    auto result = _groupApi.beginFileEncryptionAnonymously(groupId, groupPubKey, size);
    return _serializer.serialize(result);
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
