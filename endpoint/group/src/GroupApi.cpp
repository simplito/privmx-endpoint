#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/endpoint/core/JsonSerializer.hpp>

#include "privmx/endpoint/core/EventVarSerializer.hpp"
#include "privmx/endpoint/core/Validator.hpp"
#include "privmx/endpoint/group/GroupApi.hpp"
#include "privmx/endpoint/group/GroupApiImpl.hpp"
#include "privmx/endpoint/group/GroupException.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::group;

GroupApi::GroupApi() {}
GroupApi::GroupApi(const GroupApi& obj) : ExtendedPointer(obj) {}
GroupApi& GroupApi::operator=(const GroupApi& obj) {
    this->ExtendedPointer::operator=(obj);
    return *this;
}
GroupApi::GroupApi(GroupApi&& obj) : ExtendedPointer(std::move(obj)) {}
GroupApi::~GroupApi() {}

GroupApi GroupApi::create(core::Connection& connection) {
    try {
        std::shared_ptr<core::ConnectionImpl> connectionImpl = connection.getImpl();
        std::shared_ptr<GroupApiImpl> impl(new GroupApiImpl(
            connectionImpl->getGateway(), connectionImpl->getUserPrivKey(), connectionImpl->getKeyProvider(),
            connectionImpl->getHost(), connectionImpl->getEventMiddleware(), connection
        ));
        impl->attach(impl);
        return GroupApi(impl);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

GroupApi::GroupApi(const std::shared_ptr<GroupApiImpl>& impl) : ExtendedPointer(impl) {}

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
    try {
        return impl->createGroup(contextId, users, managers, publicMeta, privateMeta, policies);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void GroupApi::addGroupMembers(const GroupId& groupId, const std::vector<GroupMemberToAdd>& newMembers) {
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
    try {
        impl->addGroupMembers(groupId, newMembers);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void GroupApi::removeGroupMembers(const GroupId& groupId, const std::vector<std::string>& userIds) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    for (const std::string& userId : userIds) {
        core::Validator::validateId(userId, "field:userIds ");
    }
    try {
        impl->removeGroupMembers(groupId, userIds);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void GroupApi::updateGroup(
    const GroupId& groupId,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const int64_t version,
    const bool force,
    const bool forceGenerateNewKey,
    const std::optional<core::ContainerPolicy>& policies
) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    try {
        impl->updateGroup(groupId, publicMeta, privateMeta, version, force, forceGenerateNewKey, policies);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void GroupApi::deleteGroup(const GroupId& groupId) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    try {
        return impl->deleteGroup(groupId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

Group GroupApi::getGroup(const GroupId& groupId) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    try {
        return impl->getGroup(groupId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

core::PagingList<GroupSummary> GroupApi::listGroups(
    const std::string& contextId,
    const core::PagingQuery& pagingQuery
) {
    auto impl = getImpl();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validatePagingQuery(pagingQuery, {"createDate", "lastModificationDate"}, "field:pagingQuery ");
    try {
        return impl->listGroups(contextId, pagingQuery);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

Envelope GroupApi::encrypt(const GroupId& groupId, const core::Buffer& content) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    try {
        return impl->encrypt(groupId, content);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

DecryptedEnvelope GroupApi::decrypt(const Envelope& envelope) {
    auto impl = getImpl();
    try {
        return impl->decrypt(envelope);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

Envelope GroupApi::encryptAnonymously(
    const GroupId& groupId,
    const PubKey& groupPubKey,
    const core::Buffer& content
) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    core::Validator::validatePubKeyBase58DER(groupPubKey, "field:groupPubKey ");
    try {
        return impl->encryptAnonymously(groupId, groupPubKey, content);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

namespace {
/**
 * Ceiling on one block handed across the API, in either direction.
 *
 * Peak memory is otherwise the caller's discipline rather than a property of the API: one call carrying a
 * whole file would hold the plaintext, the ciphertext and the binding's own copies at once. That is a hard
 * failure in a WebAssembly build, where the address space is 4 GiB and the practical heap far smaller.
 * `StoreApi` bounds its random-write path the same way.
 */
constexpr size_t MAX_FILE_BLOCK = 4 * 1024 * 1024;
} // namespace

FileHandle GroupApi::beginFileEncryption(const GroupId& groupId, const FileSize size) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    if (size < 0) {
        throw core::InvalidParamsException("field:size cannot be negative");
    }
    try {
        return impl->beginFileEncryption(groupId, size);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

FileHandle GroupApi::beginFileEncryptionAnonymously(
    const GroupId& groupId,
    const PubKey& groupPubKey,
    const FileSize size
) {
    auto impl = getImpl();
    core::Validator::validateId(groupId, "field:groupId ");
    core::Validator::validatePubKeyBase58DER(groupPubKey, "field:groupPubKey ");
    if (size < 0) {
        throw core::InvalidParamsException("field:size cannot be negative");
    }
    try {
        return impl->beginFileEncryptionAnonymously(groupId, groupPubKey, size);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

core::Buffer GroupApi::encryptFileChunk(const FileHandle fileHandle, const core::Buffer& plainChunk) {
    auto impl = getImpl();
    core::Validator::validateBufferSize(plainChunk, 0, MAX_FILE_BLOCK, "field:plainChunk");
    try {
        return impl->encryptFileChunk(fileHandle, plainChunk);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

Envelope GroupApi::finishFileEncryption(const FileHandle fileHandle) {
    auto impl = getImpl();
    try {
        return impl->finishFileEncryption(fileHandle);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

FileHandle GroupApi::beginFileDecryption(const Envelope& envelope) {
    auto impl = getImpl();
    try {
        return impl->beginFileDecryption(envelope);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

core::Buffer GroupApi::decryptFileChunk(const FileHandle fileHandle, const core::Buffer& cipherChunk) {
    auto impl = getImpl();
    core::Validator::validateBufferSize(cipherChunk, 0, MAX_FILE_BLOCK, "field:cipherChunk");
    try {
        return impl->decryptFileChunk(fileHandle, cipherChunk);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

CipherOffset GroupApi::seekInEncryptedFile(const FileHandle fileHandle, const FilePosition position) {
    auto impl = getImpl();
    try {
        return impl->seekInEncryptedFile(fileHandle, position);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

DecryptedFileInfo GroupApi::finishFileDecryption(const FileHandle fileHandle) {
    auto impl = getImpl();
    try {
        return impl->finishFileDecryption(fileHandle);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::vector<std::string> GroupApi::subscribeFor(const std::vector<std::string>& subscriptionQueries) {
    auto impl = getImpl();
    try {
        return impl->subscribeFor(subscriptionQueries);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void GroupApi::unsubscribeFrom(const std::vector<std::string>& subscriptionIds) {
    auto impl = getImpl();
    try {
        return impl->unsubscribeFrom(subscriptionIds);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::string GroupApi::buildSubscriptionQuery(
    EventType eventType,
    EventSelectorType selectorType,
    const std::string& selectorId
) {
    auto impl = getImpl();
    try {
        return impl->buildSubscriptionQuery(eventType, selectorType, selectorId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}
