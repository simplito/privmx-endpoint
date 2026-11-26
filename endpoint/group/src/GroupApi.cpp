#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/endpoint/core/JsonSerializer.hpp>

#include "privmx/endpoint/core/EventVarSerializer.hpp"
#include "privmx/endpoint/core/Validator.hpp"
#include "privmx/endpoint/group/Constants.hpp"
#include "privmx/endpoint/group/GroupApi.hpp"
#include "privmx/endpoint/group/GroupApiImpl.hpp"
#include "privmx/endpoint/group/GroupException.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::group;

GroupApi GroupApi::create(core::Connection& connection) {
    std::shared_ptr<core::ConnectionImpl> connectionImpl = connection.getImpl();
    std::shared_ptr<GroupApiImpl> impl(new GroupApiImpl(
        connectionImpl->getGateway(), connectionImpl->getUserPrivKey(), connectionImpl->getKeyProvider(),
        connectionImpl->getHost(), connectionImpl->getEventMiddleware(), connection
    ));
    return GroupApi(impl);
}

GroupApi::GroupApi(const std::shared_ptr<GroupApiImpl>& impl) : BaseApiClass(impl) {}

std::string GroupApi::createGroup(
    const std::string& contextId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const std::optional<GroupRulesUpdate>& rules,
    const std::optional<core::Buffer>& idSeed,
    const std::string& visibleTo
) {
    auto impl = getImpl();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validateUserListFormat(users, "field:users ");
    core::Validator::validateUserListFormat(managers, "field:managers ");
    return impl->createGroup(contextId, users, managers, publicMeta, privateMeta, rules, idSeed, visibleTo);
}

std::string GroupApi::deriveGroupId(const std::string& contextId, const core::Buffer& idSeed) {
    core::Validator::validateId(contextId, "field:contextId ");
    return GroupApiImpl::deriveGroupId(contextId, idSeed);
}

std::vector<GroupResult> GroupApi::getGroups(const std::vector<std::string>& groupIds) {
    auto impl = getImpl();
    for (const std::string& groupId : groupIds) {
        core::Validator::validateId(groupId, "field:groupIds ");
    }
    return impl->getGroups(groupIds);
}

GroupPublicKey GroupApi::getGroupPublicKey(const std::string& contextId, const std::string& groupId) {
    auto impl = getImpl();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validateId(groupId, "field:groupId ");
    return impl->getGroupPublicKey(contextId, groupId);
}

void GroupApi::setGroupVisibility(const std::string& groupId, const std::string& visibleTo) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    impl->setGroupVisibility(groupId, visibleTo);
}

void GroupApi::addGroupMembers(const std::string& groupId, const std::vector<GroupMemberToAdd>& newMembers) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    if (newMembers.empty()) {
        // Caught here rather than on the wire: the seat request the impl derives from this size would be
        // rejected by `groupGet`'s own bounds, naming a field the caller never set.
        throw core::InvalidParamsException("field:newMembers must name at least one member");
    }
    std::vector<core::UserWithPubKey> asRoster;
    for (const GroupMemberToAdd& newMember : newMembers) {
        if (newMember.role != "user" && newMember.role != "manager") {
            throw core::InvalidParamsException("field:newMembers.role must be \"user\" or \"manager\"");
        }
        asRoster.push_back(newMember.user);
    }
    core::Validator::validateUserListFormat(asRoster, "field:newMembers ");
    impl->addGroupMembers(groupId, newMembers);
}

int64_t GroupApi::removeGroupMembers(const std::string& groupId, const std::vector<std::string>& userIds) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    for (const std::string& userId : userIds) {
        core::Validator::validateId(userId, "field:userIds ");
    }
    return impl->removeGroupMembers(groupId, userIds);
}

int64_t GroupApi::replaceGroupMemberKeys(const std::string& groupId, const std::vector<std::string>& userIds) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    for (const std::string& userId : userIds) {
        core::Validator::validateId(userId, "field:userIds ");
    }
    return impl->replaceGroupMemberKeys(groupId, userIds);
}

void GroupApi::setGroupRoles(const std::string& groupId, const std::vector<GroupRoleChange>& changes) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    for (const GroupRoleChange& change : changes) {
        core::Validator::validateId(change.userId, "field:changes ");
    }
    impl->setGroupRoles(groupId, changes);
}

void GroupApi::updateGroupRules(const std::string& groupId, const GroupRulesUpdate& rules) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    impl->updateGroupRules(groupId, rules);
}

core::PagingList<GroupLogEntry> GroupApi::getGroupLog(
    const std::string& groupId,
    const core::PagingQuery& pagingQuery
) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    return impl->getGroupLog(groupId, pagingQuery);
}

int64_t GroupApi::rotateGroupKey(const std::string& groupId) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    return impl->rotateGroupKey(groupId);
}

int64_t GroupApi::cutHistory(const std::string& groupId) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    return impl->cutHistory(groupId);
}

bool GroupApi::renewLeaf(const std::string& groupId, const std::string& previousUserPrivKey) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    core::Validator::validatePrivKeyWIF(previousUserPrivKey, "field:previousUserPrivKey ");
    return impl->renewLeaf(groupId, previousUserPrivKey);
}

void GroupApi::updateGroupPublicMeta(
    const std::string& groupId,
    const core::Buffer& publicMeta,
    const int64_t version
) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    impl->updateGroupPublicMeta(groupId, publicMeta, version);
}

void GroupApi::updateGroupPrivateMeta(
    const std::string& groupId,
    const core::Buffer& privateMeta,
    const int64_t version
) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    impl->updateGroupPrivateMeta(groupId, privateMeta, version);
}

void GroupApi::deleteGroup(const std::string& groupId) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    return impl->deleteGroup(groupId);
}

Group GroupApi::getGroup(const std::string& groupId) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    return impl->getGroup(groupId);
}

core::PagingList<GroupSummary> GroupApi::listGroups(
    const std::string& contextId,
    const core::PagingQuery& pagingQuery
) {
    auto impl = getImpl();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validatePagingQuery(pagingQuery, {"createDate", "lastModificationDate"}, "field:pagingQuery ");
    return impl->listGroups(contextId, pagingQuery);
}

Path GroupApi::noLocation() {
    return GroupApiImpl::noLocation();
}
core::Buffer GroupApi::idFromString(const std::string& identifier) {
    return GroupApiImpl::idFromString(identifier);
}
EnvelopeHeader GroupApi::peekEnvelope(const core::Buffer& envelope) {
    return GroupApiImpl::peekEnvelope(envelope);
}
Envelope GroupApi::encrypt(
    const std::string& groupId,
    const Path& location,
    const core::Buffer& content,
    const EncryptOptions& options
) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    return impl->encrypt(groupId, location, content, options);
}
DecryptedEnvelope GroupApi::decrypt(
    const std::string& groupId,
    const Path& location,
    const Envelope& envelope,
    const DecryptOptions& options
) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    return impl->decrypt(groupId, location, envelope, options);
}
std::vector<DecryptResult> GroupApi::decryptMany(const std::string& groupId, const std::vector<DecryptItem>& items) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    return impl->decryptMany(groupId, items);
}
Envelope GroupApi::encryptAsOutsider(
    const std::string& contextId,
    const std::string& groupId,
    const Path& location,
    const core::Buffer& content,
    const EncryptOptions& options
) {
    auto impl = getImpl();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validateId(groupId, "field:groupId ");
    return impl->encryptAsOutsider(contextId, groupId, location, content, options);
}
Envelope GroupApi::encryptAnonymously(
    const std::string& groupId,
    const std::string& groupPubKey,
    const Path& location,
    const core::Buffer& content
) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    core::Validator::validatePubKeyBase58DER(groupPubKey, "field:groupPubKey ");
    return impl->encryptAnonymously(groupId, groupPubKey, location, content);
}
DecryptedOutsiderEnvelope GroupApi::decryptFromOutsider(
    const std::string& groupId,
    const Path& location,
    const Envelope& envelope,
    const DecryptOptions& options
) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    return impl->decryptFromOutsider(groupId, location, envelope, options);
}
DecryptedAnonymousEnvelope GroupApi::decryptAnonymous(
    const std::string& groupId,
    const Path& location,
    const Envelope& envelope
) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    return impl->decryptAnonymous(groupId, location, envelope);
}
DecryptedSharedEnvelope GroupApi::decryptShared(
    const std::string& contextId,
    const Path& location,
    const Envelope& envelope,
    const DecryptOptions& options
) {
    auto impl = getImpl();
    core::Validator::validateId(contextId, "field:contextId ");
    return impl->decryptShared(contextId, location, envelope, options);
}

FileHandle GroupApi::beginFileEncryption(
    const std::string& groupId,
    const Path& location,
    const EncryptOptions& options
) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    return impl->beginFileEncryption(groupId, location, options);
}

FileHandle GroupApi::beginFileEncryptionAsOutsider(
    const std::string& contextId,
    const std::string& groupId,
    const Path& location,
    const EncryptOptions& options
) {
    auto impl = getImpl();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validateId(groupId, "field:groupId ");
    return impl->beginFileEncryptionAsOutsider(contextId, groupId, location, options);
}

FileHandle GroupApi::beginFileEncryptionAnonymously(
    const std::string& groupId,
    const std::string& groupPubKey,
    const Path& location
) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    core::Validator::validatePubKeyBase58DER(groupPubKey, "field:groupPubKey ");
    return impl->beginFileEncryptionAnonymously(groupId, groupPubKey, location);
}

core::Buffer GroupApi::encryptFileChunk(const FileHandle fileHandle, const core::Buffer& plainChunk) {
    auto impl = getImpl();
    core::Validator::validateBufferSize(plainChunk, 0, MAX_FILE_BLOCK, "field:plainChunk");
    return impl->encryptFileChunk(fileHandle, plainChunk);
}

Envelope GroupApi::finishFileEncryption(const FileHandle fileHandle) {
    auto impl = getImpl();
    return impl->finishFileEncryption(fileHandle);
}

void GroupApi::abortFile(const FileHandle fileHandle) {
    auto impl = getImpl();
    impl->abortFile(fileHandle);
}

FileHandle GroupApi::beginFileDecryption(
    const std::string& groupId,
    const Path& location,
    const Envelope& envelope,
    const DecryptOptions& options
) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    return impl->beginFileDecryption(groupId, location, envelope, options);
}

FileHandle GroupApi::beginFileDecryptionFromOutsider(
    const std::string& groupId,
    const Path& location,
    const Envelope& envelope,
    const DecryptOptions& options
) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    return impl->beginFileDecryptionFromOutsider(groupId, location, envelope, options);
}

FileHandle GroupApi::beginAnonymousFileDecryption(
    const std::string& groupId,
    const Path& location,
    const Envelope& envelope
) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    return impl->beginAnonymousFileDecryption(groupId, location, envelope);
}

FileHandle GroupApi::beginSharedFileDecryption(
    const std::string& contextId,
    const Path& location,
    const Envelope& envelope,
    const DecryptOptions& options
) {
    auto impl = getImpl();
    core::Validator::validateId(contextId, "field:contextId ");
    return impl->beginSharedFileDecryption(contextId, location, envelope, options);
}

core::Buffer GroupApi::decryptFileChunk(const FileHandle fileHandle, const core::Buffer& cipherChunk) {
    auto impl = getImpl();
    core::Validator::validateBufferSize(cipherChunk, 0, MAX_FILE_BLOCK, "field:cipherChunk");
    return impl->decryptFileChunk(fileHandle, cipherChunk);
}

CipherRange GroupApi::getFileCipherRange(const FileHandle fileHandle, const FilePosition from, const FilePosition to) {
    auto impl = getImpl();
    return impl->getFileCipherRange(fileHandle, from, to);
}

CipherOffset GroupApi::seekInEncryptedFile(const FileHandle fileHandle, const FilePosition position) {
    auto impl = getImpl();
    return impl->seekInEncryptedFile(fileHandle, position);
}

DecryptedFileInfo GroupApi::finishFileDecryption(const FileHandle fileHandle) {
    auto impl = getImpl();
    return impl->finishFileDecryption(fileHandle);
}

SequenceHandle GroupApi::beginSequence(const std::string& groupId, const Path& location, int64_t checkpointEvery) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    return impl->beginSequence(groupId, location, checkpointEvery);
}

core::Buffer GroupApi::getSequenceHeader(const SequenceHandle sequence) {
    auto impl = getImpl();
    return impl->getSequenceHeader(sequence);
}

SequenceAppendResult GroupApi::appendToSequence(const SequenceHandle sequence, const core::Buffer& data) {
    auto impl = getImpl();
    return impl->appendToSequence(sequence, data);
}

core::Buffer GroupApi::checkpointSequence(const SequenceHandle sequence) {
    auto impl = getImpl();
    return impl->checkpointSequence(sequence);
}

core::Buffer GroupApi::finishSequence(const SequenceHandle sequence) {
    auto impl = getImpl();
    return impl->finishSequence(sequence);
}

SequenceHandle GroupApi::openSequence(
    const std::string& groupId,
    const Path& location,
    const core::Buffer& header,
    const DecryptOptions& options,
    const std::optional<core::Buffer>& resumeFrom
) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    return impl->openSequence(groupId, location, header, options, resumeFrom);
}

SequenceItem GroupApi::readSequenceItem(const SequenceHandle sequence, const core::Buffer& item) {
    auto impl = getImpl();
    return impl->readSequenceItem(sequence, item);
}

SequenceMarkInfo GroupApi::verifySequenceMark(const SequenceHandle sequence, const core::Buffer& mark) {
    auto impl = getImpl();
    return impl->verifySequenceMark(sequence, mark);
}

void GroupApi::closeSequence(const SequenceHandle sequence) {
    auto impl = getImpl();
    impl->closeSequence(sequence);
}

SequenceItemHeader GroupApi::peekSequenceItem(const core::Buffer& itemOrMark) {
    return GroupApiImpl::peekSequenceItem(itemOrMark);
}

std::string GroupApi::createSpace(
    const std::string& contextId,
    const std::vector<SpaceRecipient>& recipients,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const std::optional<core::Buffer>& idSeed
) {
    auto impl = getImpl();
    core::Validator::validateId(contextId, "field:contextId ");
    return impl->createSpace(contextId, recipients, publicMeta, privateMeta, idSeed);
}

std::string GroupApi::deriveSpaceId(const std::string& contextId, const core::Buffer& idSeed) {
    core::Validator::validateId(contextId, "field:contextId ");
    return GroupApiImpl::deriveSpaceId(contextId, idSeed);
}

core::Buffer GroupApi::encodePath(const Path& path) {
    return GroupApiImpl::encodePath(path);
}

void GroupApi::pinGroupToSubject(const std::string& contextId, const Path& subject, const std::string& groupId) {
    auto impl = getImpl();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validateId(groupId, "field:groupId ");
    impl->pinGroupToSubject(contextId, subject, groupId);
}

SpaceState GroupApi::getSpace(const std::string& spaceId) {
    auto impl = getImpl();
    core::Validator::validateId(spaceId, "field:spaceId ");
    return impl->getSpace(spaceId);
}

core::PagingList<SpaceState> GroupApi::listSpaces(const std::string& contextId, const core::PagingQuery& pagingQuery) {
    auto impl = getImpl();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validatePagingQuery(pagingQuery, {"createDate", "lastModificationDate"}, "field:pagingQuery ");
    return impl->listSpaces(contextId, pagingQuery);
}

void GroupApi::deleteSpace(const std::string& spaceId) {
    auto impl = getImpl();
    core::Validator::validateId(spaceId, "field:spaceId ");
    impl->deleteSpace(spaceId);
}

void GroupApi::addSpaceRecipients(const std::string& spaceId, const std::vector<SpaceRecipient>& recipients) {
    auto impl = getImpl();
    core::Validator::validateId(spaceId, "field:spaceId ");
    impl->addSpaceRecipients(spaceId, recipients);
}

int64_t GroupApi::removeSpaceRecipients(const std::string& spaceId, const std::vector<SpaceRecipientRef>& recipients) {
    auto impl = getImpl();
    core::Validator::validateId(spaceId, "field:spaceId ");
    return impl->removeSpaceRecipients(spaceId, recipients);
}

int64_t GroupApi::rotateSpaceKey(const std::string& spaceId) {
    auto impl = getImpl();
    core::Validator::validateId(spaceId, "field:spaceId ");
    return impl->rotateSpaceKey(spaceId);
}

void GroupApi::updateSpacePublicMeta(const std::string& spaceId, const core::Buffer& meta, int64_t version) {
    auto impl = getImpl();
    core::Validator::validateId(spaceId, "field:spaceId ");
    impl->updateSpacePublicMeta(spaceId, meta, version);
}

void GroupApi::updateSpacePrivateMeta(const std::string& spaceId, const core::Buffer& meta, int64_t version) {
    auto impl = getImpl();
    core::Validator::validateId(spaceId, "field:spaceId ");
    impl->updateSpacePrivateMeta(spaceId, meta, version);
}

core::Buffer GroupApi::encryptInSpace(const std::string& spaceId, const Path& location, const core::Buffer& data) {
    auto impl = getImpl();
    core::Validator::validateId(spaceId, "field:spaceId ");
    return impl->encryptInSpace(spaceId, location, data);
}

DecryptedSpaceEnvelope GroupApi::decryptInSpace(
    const std::string& spaceId,
    const Path& location,
    const core::Buffer& envelope,
    const DecryptOptions& options
) {
    auto impl = getImpl();
    core::Validator::validateId(spaceId, "field:spaceId ");
    return impl->decryptInSpace(spaceId, location, envelope, options);
}

std::vector<SpaceDecryptResult> GroupApi::decryptManyInSpace(
    const std::string& spaceId,
    const std::vector<DecryptItem>& items
) {
    auto impl = getImpl();
    core::Validator::validateId(spaceId, "field:spaceId ");
    return impl->decryptManyInSpace(spaceId, items);
}

FileHandle GroupApi::beginFileEncryptionInSpace(const std::string& spaceId, const Path& location) {
    auto impl = getImpl();
    core::Validator::validateId(spaceId, "field:spaceId ");
    return impl->beginFileEncryptionInSpace(spaceId, location);
}

FileHandle GroupApi::beginFileDecryptionInSpace(
    const std::string& spaceId,
    const Path& location,
    const core::Buffer& envelope,
    const DecryptOptions& options
) {
    auto impl = getImpl();
    core::Validator::validateId(spaceId, "field:spaceId ");
    return impl->beginFileDecryptionInSpace(spaceId, location, envelope, options);
}

SequenceHandle GroupApi::beginSequenceInSpace(
    const std::string& spaceId,
    const Path& location,
    int64_t checkpointEvery
) {
    auto impl = getImpl();
    core::Validator::validateId(spaceId, "field:spaceId ");
    return impl->beginSequenceInSpace(spaceId, location, checkpointEvery);
}

SequenceHandle GroupApi::openSequenceInSpace(
    const std::string& spaceId,
    const Path& location,
    const core::Buffer& header,
    const DecryptOptions& options,
    const std::optional<core::Buffer>& resumeFrom
) {
    auto impl = getImpl();
    core::Validator::validateId(spaceId, "field:spaceId ");
    return impl->openSequenceInSpace(spaceId, location, header, options, resumeFrom);
}

SpaceOrigin GroupApi::getSpaceSequenceOrigin(const SequenceHandle sequence) {
    auto impl = getImpl();
    return impl->getSpaceSequenceOrigin(sequence);
}

core::PagingList<SpaceLogEntry> GroupApi::getSpaceLog(
    const std::string& spaceId,
    const core::PagingQuery& pagingQuery
) {
    auto impl = getImpl();
    core::Validator::validateId(spaceId, "field:spaceId ");
    return impl->getSpaceLog(spaceId, pagingQuery);
}

std::vector<std::string> GroupApi::subscribeFor(const std::vector<std::string>& subscriptionQueries) {
    auto impl = getImpl();
    return impl->subscribeFor(subscriptionQueries);
}

void GroupApi::unsubscribeFrom(const std::vector<std::string>& subscriptionIds) {
    auto impl = getImpl();
    return impl->unsubscribeFrom(subscriptionIds);
}

std::string GroupApi::buildSubscriptionQuery(
    EventType eventType,
    EventSelectorType selectorType,
    const std::string& selectorId
) {
    auto impl = getImpl();
    return impl->buildSubscriptionQuery(eventType, selectorType, selectorId);
}

void GroupApi::sendCustomEvent(
    const std::string& groupId,
    const std::string& channelName,
    const core::Buffer& eventData,
    const std::vector<std::string>& users
) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    core::Validator::validateBufferSize(eventData, 0, MAX_CUSTOM_EVENT_DATA, "field:eventData ");
    for (const auto& user : users) {
        core::Validator::validateId(user, "field:users ");
    }
    return impl->sendCustomEvent(groupId, channelName, eventData, users);
}

std::string GroupApi::buildCustomEventSubscriptionQuery(
    const std::string& channelName,
    EventSelectorType selectorType,
    const std::string& selectorId
) {
    auto impl = getImpl();
    return impl->buildCustomEventSubscriptionQuery(channelName, selectorType, selectorId);
}
