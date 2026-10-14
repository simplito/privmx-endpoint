/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/endpoint/core/JsonSerializer.hpp>
#include <privmx/endpoint/core/Validator.hpp>
#include <privmx/endpoint/store/FileDataProvider.hpp>

#include "privmx/endpoint/core/EventVarSerializer.hpp"
#include "privmx/endpoint/inbox/InboxApi.hpp"
#include "privmx/endpoint/inbox/InboxApiImpl.hpp"
#include "privmx/endpoint/inbox/InboxException.hpp"

using namespace privmx::endpoint::inbox;
using namespace privmx::endpoint;

InboxApi InboxApi::create(
    core::Connection& connection,
    thread::ThreadApi& threadApi,
    store::StoreApi& storeApi,
    const std::optional<group::GroupApi>& groupApi
) {
    std::shared_ptr<core::ConnectionImpl> connectionImpl = connection.getImpl();
    std::shared_ptr<store::RequestApi> requestApi{new store::RequestApi(connectionImpl->getGateway())};
    std::shared_ptr<ServerApi> serverApi{new ServerApi(connectionImpl->getGateway())};
    std::shared_ptr<InboxApiImpl> impl(new InboxApiImpl(
        connection, threadApi, storeApi, connectionImpl->getKeyProvider(), serverApi, requestApi,
        connectionImpl->getHost(), connectionImpl->getUserPrivKey(), connectionImpl->getEventMiddleware(),
        connectionImpl->getHandleManager(), connectionImpl->getServerConfig().requestChunkSize, groupApi
    ));
    return InboxApi(impl);
}

InboxApi::InboxApi(const std::shared_ptr<InboxApiImpl>& impl) : BaseApiClass(impl) {}

std::string InboxApi::createInbox(
    const std::string& contextId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const std::optional<inbox::FilesConfig>& filesConfig,
    const std::optional<core::ContainerPolicyWithoutItem>& policies,
    const std::vector<core::GroupGrantWithKey>& groups
) {
    auto impl = getImpl();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    core::Validator::validateClass<std::vector<core::GroupGrantWithKey>>(groups, "field:groups ");
    return impl->createInbox(contextId, users, managers, publicMeta, privateMeta, filesConfig, policies, groups);
}

void InboxApi::updateInbox(
    const std::string& inboxId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const std::optional<inbox::FilesConfig>& filesConfig,
    const int64_t version,
    const bool force,
    const bool forceGenerateNewKey,
    const std::optional<core::ContainerPolicyWithoutItem>& policies,
    const std::vector<core::GroupGrantWithKey>& groups
) {
    auto impl = getImpl();
    core::Validator::validateId(inboxId, "field:inboxId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    core::Validator::validateClass<std::vector<core::GroupGrantWithKey>>(groups, "field:groups ");
    return impl->updateInbox(
        inboxId, users, managers, publicMeta, privateMeta, filesConfig, version, force, forceGenerateNewKey, policies,
        groups
    );
}

void InboxApi::rotateInboxKeys(
    const std::string& inboxId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const int64_t version,
    const bool force,
    const std::vector<core::GroupGrantWithKey>& groups
) {
    auto impl = getImpl();
    core::Validator::validateId(inboxId, "field:inboxId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    core::Validator::validateClass<std::vector<core::GroupGrantWithKey>>(groups, "field:groups ");
    impl->rotateInboxKeys(inboxId, users, managers, version, force, groups);
}

Inbox InboxApi::getInbox(const std::string& inboxId) {
    auto impl = getImpl();
    core::Validator::validateId(inboxId, "field:inboxId ");
    return impl->getInbox(inboxId);
}

core::PagingList<inbox::Inbox> InboxApi::listInboxes(const std::string& contextId, const core::PagingQuery& query) {
    auto impl = getImpl();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validatePagingQuery(query, {"createDate", "lastModificationDate"}, "field:query ");
    return impl->listInboxes(contextId, query);
}

InboxPublicView InboxApi::getInboxPublicView(const std::string& inboxId) {
    auto impl = getImpl();
    core::Validator::validateId(inboxId, "field:inboxId ");
    return impl->getInboxPublicView(inboxId);
}

void InboxApi::deleteInbox(const std::string& inboxId) {
    auto impl = getImpl();
    core::Validator::validateId(inboxId, "field:inboxId ");
    return impl->deleteInbox(inboxId);
}

int64_t /*inboxHandle*/ InboxApi::prepareEntry(
    const std::string& inboxId,
    const core::Buffer& data,
    const std::vector<int64_t>& inboxFileHandles,
    const std::optional<std::string>& userPrivKey
) {
    auto impl = getImpl();
    core::Validator::validateId(inboxId, "field:inboxId ");
    if (userPrivKey.has_value()) {
        core::Validator::validatePrivKeyWIF(userPrivKey.value());
    }
    return impl->prepareEntry(inboxId, data, inboxFileHandles, userPrivKey);
}

void InboxApi::sendEntry(const int64_t inboxHandle) {
    auto impl = getImpl();
    return impl->sendEntry(inboxHandle);
}

inbox::InboxEntry InboxApi::readEntry(const std::string& inboxEntryId) {
    auto impl = getImpl();
    core::Validator::validateId(inboxEntryId, "field:inboxEntryId ");
    return impl->readEntry(inboxEntryId);
}

void InboxApi::deleteEntry(const std::string& inboxEntryId) {
    auto impl = getImpl();
    core::Validator::validateId(inboxEntryId, "field:inboxEntryId ");
    return impl->deleteEntry(inboxEntryId);
}

core::PagingList<inbox::InboxEntry> InboxApi::listEntries(const std::string& inboxId, const core::PagingQuery& query) {
    auto impl = getImpl();
    core::Validator::validateId(inboxId, "field:inboxId ");
    core::Validator::validatePagingQuery(query, {"createDate"}, "field:query ");
    return impl->listEntries(inboxId, query);
}

int64_t /*inboxFileHandle*/ InboxApi::createFileHandle(
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const int64_t& fileSize
) {
    auto impl = getImpl();
    core::Validator::validateNumberNonNegative(fileSize, "field:fileSize ");
    return impl->createFileHandle(publicMeta, privateMeta, fileSize);
}

void InboxApi::writeToFile(const int64_t inboxHandle, const int64_t inboxFileHandle, const core::Buffer& dataChunk) {
    auto impl = getImpl();
    return impl->writeToFile(inboxHandle, inboxFileHandle, dataChunk);
}

int64_t InboxApi::openFile(const std::string& fileId) {
    auto impl = getImpl();
    core::Validator::validateId(fileId, "field:fileId ");
    return impl->openFile(fileId);
}

core::Buffer InboxApi::readFromFile(const int64_t handle, const int64_t length) {
    auto impl = getImpl();
    core::Validator::validateNumberNonNegative(length, "field:length ");
    return impl->readFromFile(handle, length);
}

void InboxApi::seekInFile(const int64_t handle, const int64_t pos) {
    auto impl = getImpl();
    core::Validator::validateNumberNonNegative(pos, "field:pos ");
    return impl->seekInFile(handle, pos);
}

std::string InboxApi::closeFile(const int64_t handle) {
    auto impl = getImpl();
    return impl->closeFile(handle);
}

std::vector<std::string> InboxApi::subscribeFor(const std::vector<std::string>& subscriptionQueries) {
    auto impl = getImpl();
    return impl->subscribeFor(subscriptionQueries);
}

void InboxApi::unsubscribeFrom(const std::vector<std::string>& subscriptionIds) {
    auto impl = getImpl();
    return impl->unsubscribeFrom(subscriptionIds);
}

std::string InboxApi::buildSubscriptionQuery(
    EventType eventType,
    EventSelectorType selectorType,
    const std::string& selectorId
) {
    auto impl = getImpl();
    return impl->buildSubscriptionQuery(eventType, selectorType, selectorId);
}