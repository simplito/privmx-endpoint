/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/endpoint/core/JsonSerializer.hpp>

#include "privmx/endpoint/core/EventVarSerializer.hpp"
#include "privmx/endpoint/thread/ThreadApi.hpp"
#include "privmx/endpoint/thread/ThreadApiImpl.hpp"
#include "privmx/endpoint/thread/ThreadException.hpp"
#include "privmx/endpoint/thread/ThreadValidator.hpp"
#include <privmx/endpoint/group/GroupApi.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::thread;

ThreadApi ThreadApi::create(core::Connection& connection, const std::optional<group::GroupApi>& groupApi) {
    std::shared_ptr<core::ConnectionImpl> connectionImpl = connection.getImpl();
    std::shared_ptr<ThreadApiImpl> impl(new ThreadApiImpl(
        connectionImpl->getGateway(), connectionImpl->getUserPrivKey(), connectionImpl->getKeyProvider(),
        connectionImpl->getHost(), connectionImpl->getEventMiddleware(), connection, groupApi
    ));
    return ThreadApi(impl);
}

ThreadApi::ThreadApi(const std::shared_ptr<ThreadApiImpl>& impl) : BaseApiClass(impl) {}

std::string ThreadApi::createThread(
    const std::string& contextId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const std::optional<core::ContainerPolicy>& policies,
    const std::vector<core::GroupGrantWithKey>& groups
) {
    auto impl = getImpl();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    core::Validator::validateClass<std::vector<core::GroupGrantWithKey>>(groups, "field:groups ");
    return impl->createThread(contextId, users, managers, publicMeta, privateMeta, policies, "thread", groups);
}

void ThreadApi::updateThread(
    const std::string& threadId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const int64_t version,
    const bool force,
    const bool forceGenerateNewKey,
    const std::optional<core::ContainerPolicy>& policies,
    const std::vector<core::GroupGrantWithKey>& groups
) {
    auto impl = getImpl();
    core::Validator::validateId(threadId, "field:threadId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    core::Validator::validateClass<std::vector<core::GroupGrantWithKey>>(groups, "field:groups ");
    impl->updateThread(
        threadId, users, managers, publicMeta, privateMeta, version, force, forceGenerateNewKey, policies, groups
    );
}

void ThreadApi::rotateThreadKeys(
    const std::string& threadId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const int64_t version,
    const bool force,
    const std::vector<core::GroupGrantWithKey>& groups
) {
    auto impl = getImpl();
    core::Validator::validateId(threadId, "field:threadId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    core::Validator::validateClass<std::vector<core::GroupGrantWithKey>>(groups, "field:groups ");
    impl->rotateThreadKeys(threadId, users, managers, version, force, groups);
}

void ThreadApi::deleteThread(const std::string& threadId) {
    auto impl = getImpl();
    core::Validator::validateId(threadId, "field:threadId ");
    return impl->deleteThread(threadId);
}

Thread ThreadApi::getThread(const std::string& threadId) {
    auto impl = getImpl();
    core::Validator::validateId(threadId, "field:threadId ");
    return impl->getThread(threadId);
}

core::PagingList<Thread> ThreadApi::listThreads(const std::string& contextId, const core::PagingQuery& pagingQuery) {
    auto impl = getImpl();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validatePagingQuery(
        pagingQuery, {"createDate", "lastModificationDate", "lastMsgDate"}, "field:pagingQuery "
    );
    return impl->listThreads(contextId, pagingQuery);
}

Message ThreadApi::getMessage(const std::string& messageId) {
    auto impl = getImpl();
    core::Validator::validateId(messageId, "field:messageId ");
    return impl->getMessage(messageId);
}

core::PagingList<Message> ThreadApi::listMessages(const std::string& threadId, const core::PagingQuery& pagingQuery) {
    auto impl = getImpl();
    core::Validator::validateId(threadId, "field:threadId ");
    core::Validator::validatePagingQuery(pagingQuery, {"createDate", "updates"}, "field:pagingQuery ");
    return impl->listMessages(threadId, pagingQuery);
}

std::string ThreadApi::sendMessage(
    const std::string& threadId,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const core::Buffer& data
) {
    auto impl = getImpl();
    core::Validator::validateId(threadId, "field:threadId ");
    return impl->sendMessage(threadId, publicMeta, privateMeta, data);
}

void ThreadApi::deleteMessage(const std::string& messageId) {
    auto impl = getImpl();
    core::Validator::validateId(messageId, "field:messageId ");
    return impl->deleteMessage(messageId);
}

void ThreadApi::updateMessage(
    const std::string& messageId,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const core::Buffer& data
) {
    auto impl = getImpl();
    core::Validator::validateId(messageId, "field:messageId ");
    return impl->updateMessage(messageId, publicMeta, privateMeta, data);
}

std::vector<std::string> ThreadApi::subscribeFor(const std::vector<std::string>& subscriptionQueries) {
    return getImpl()->subscribeFor(subscriptionQueries);
}

void ThreadApi::unsubscribeFrom(const std::vector<std::string>& subscriptionIds) {
    return getImpl()->unsubscribeFrom(subscriptionIds);
}

std::string ThreadApi::buildSubscriptionQuery(
    EventType eventType,
    EventSelectorType selectorType,
    const std::string& selectorId
) {
    return getImpl()->buildSubscriptionQuery(eventType, selectorType, selectorId);
}
