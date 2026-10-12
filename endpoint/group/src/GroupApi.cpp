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
    const std::optional<core::ContainerPolicy>& policies
) {
    auto impl = getImpl();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validateUserListFormat(users, "field:users ");
    core::Validator::validateUserListFormat(managers, "field:managers ");
    return impl->createGroup(contextId, users, managers, publicMeta, privateMeta, policies);
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

void GroupApi::removeGroupMembers(const std::string& groupId, const std::vector<std::string>& userIds) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    for (const std::string& userId : userIds) {
        core::Validator::validateId(userId, "field:userIds ");
    }
    impl->removeGroupMembers(groupId, userIds);
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

void GroupApi::updateGroupPolicy(const std::string& groupId, const core::ContainerPolicy& policies) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    impl->updateGroupPolicy(groupId, policies);
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

Envelope GroupApi::encrypt(const std::string& groupId, const core::Buffer& content) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    return impl->encrypt(groupId, content);
}

DecryptedEnvelope GroupApi::decrypt(const Envelope& envelope) {
    auto impl = getImpl();
    return impl->decrypt(envelope);
}

Envelope GroupApi::encryptAnonymously(
    const std::string& groupId,
    const std::string& groupPubKey,
    const core::Buffer& content
) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    core::Validator::validatePubKeyBase58DER(groupPubKey, "field:groupPubKey ");
    return impl->encryptAnonymously(groupId, groupPubKey, content);
}

namespace {
// Ceiling on one block handed across the API, so peak memory is a property of the API rather than the
// caller's discipline — a whole-file call would be a hard failure under WebAssembly's 4 GiB address space.
constexpr size_t MAX_FILE_BLOCK = 4 * 1024 * 1024;
} // namespace

FileHandle GroupApi::beginFileEncryption(const std::string& groupId, const FileSize size) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    if (size < 0) {
        throw core::InvalidParamsException("field:size cannot be negative");
    }
    return impl->beginFileEncryption(groupId, size);
}

FileHandle GroupApi::beginFileEncryptionAnonymously(
    const std::string& groupId,
    const std::string& groupPubKey,
    const FileSize size
) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    core::Validator::validatePubKeyBase58DER(groupPubKey, "field:groupPubKey ");
    if (size < 0) {
        throw core::InvalidParamsException("field:size cannot be negative");
    }
    return impl->beginFileEncryptionAnonymously(groupId, groupPubKey, size);
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

FileHandle GroupApi::beginFileDecryption(const Envelope& envelope) {
    auto impl = getImpl();
    return impl->beginFileDecryption(envelope);
}

core::Buffer GroupApi::decryptFileChunk(const FileHandle fileHandle, const core::Buffer& cipherChunk) {
    auto impl = getImpl();
    core::Validator::validateBufferSize(cipherChunk, 0, MAX_FILE_BLOCK, "field:cipherChunk");
    return impl->decryptFileChunk(fileHandle, cipherChunk);
}

CipherOffset GroupApi::seekInEncryptedFile(const FileHandle fileHandle, const FilePosition position) {
    auto impl = getImpl();
    return impl->seekInEncryptedFile(fileHandle, position);
}

DecryptedFileInfo GroupApi::finishFileDecryption(const FileHandle fileHandle) {
    auto impl = getImpl();
    return impl->finishFileDecryption(fileHandle);
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
