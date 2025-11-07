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
#include <privmx/endpoint/core/ExceptionConverter.hpp>

#include "privmx/endpoint/thread/ThreadApi.hpp"
#include "privmx/endpoint/thread/ThreadApiImpl.hpp"
#include "privmx/endpoint/thread/ThreadException.hpp"
#include "privmx/endpoint/thread/ThreadValidator.hpp"
#include "privmx/endpoint/core/EventVarSerializer.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::thread;

ThreadApi ThreadApi::create(core::Connection& connection) {
    try {
        return ThreadApi(connection);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

ThreadApi::ThreadApi(core::Connection& connection) {
    std::shared_ptr<core::ConnectionImpl> connectionImpl = connection.getImpl();
    _threadApiImpl = std::make_shared<ThreadApiImpl>(
        std::bind(&ThreadApi::onConnectionLost, this),
        connectionImpl->getGateway(),
        connectionImpl->getUserPrivKey(),
        connectionImpl->getKeyProvider(),
        connectionImpl->getHost(),
        connectionImpl->getEventMiddleware(),
        connection
    );
}

void ThreadApi::onConnectionLost() {
    std::unique_lock<std::shared_mutex> lock(*_threadApiImplMutex);
    _threadApiImpl.reset();
}
std::shared_ptr<ThreadApiImpl> ThreadApi::getImpl() const { 
    std::shared_lock lock(*_threadApiImplMutex);
    if(_threadApiImpl == nullptr) throw NotInitializedException();
    return _threadApiImpl; 
}

std::string ThreadApi::createThread(
    const std::string& contextId, 
    const std::vector<core::UserWithPubKey>& users, 
    const std::vector<core::UserWithPubKey>& managers,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const std::optional<core::ContainerPolicy>& policies
) {
    auto impl = getImpl();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    try {
        return impl->createThread(contextId, users, managers, publicMeta, privateMeta, policies);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
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
    const std::optional<core::ContainerPolicy>& policies
) {
    auto impl = getImpl();
    core::Validator::validateId(threadId, "field:threadId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    try {
        impl->updateThread(threadId, users, managers, publicMeta, privateMeta, version, force, forceGenerateNewKey, policies);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void ThreadApi::deleteThread(const std::string& threadId) {
    auto impl = getImpl();
    core::Validator::validateId(threadId, "field:threadId ");
    try {
        return impl->deleteThread(threadId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

Thread ThreadApi::getThread(const std::string& threadId) {
    auto impl = getImpl();
    core::Validator::validateId(threadId, "field:threadId ");
    try {
        return impl->getThread(threadId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

core::PagingList<Thread> ThreadApi::listThreads(const std::string& contextId, const core::PagingQuery& pagingQuery) {
    auto impl = getImpl();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validatePagingQuery(pagingQuery, {"createDate", "lastModificationDate", "lastMsgDate"}, "field:pagingQuery ");
    try {
        return impl->listThreads(contextId, pagingQuery);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

Message ThreadApi::getMessage(const std::string& messageId) {
    auto impl = getImpl();
    core::Validator::validateId(messageId, "field:messageId ");
    try {
        return impl->getMessage(messageId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

core::PagingList<Message> ThreadApi::listMessages(const std::string& threadId, const core::PagingQuery& pagingQuery) {
    auto impl = getImpl();
    core::Validator::validateId(threadId, "field:threadId ");
    core::Validator::validatePagingQuery(pagingQuery, {"createDate", "updates"}, "field:pagingQuery ");
    try {
        return impl->listMessages(threadId, pagingQuery);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::string ThreadApi::sendMessage(const std::string& threadId, const core::Buffer& publicMeta, const core::Buffer& privateMeta, const core::Buffer& data) {
    auto impl = getImpl();
    core::Validator::validateId(threadId, "field:threadId ");
    try {
        return impl->sendMessage(threadId, publicMeta, privateMeta, data);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void ThreadApi::deleteMessage(const std::string& messageId) {
    auto impl = getImpl();
    core::Validator::validateId(messageId, "field:messageId ");
    try {
        return impl->deleteMessage(messageId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void ThreadApi::updateMessage(const std::string& messageId, const core::Buffer& publicMeta, const core::Buffer& privateMeta, const core::Buffer& data) {
    auto impl = getImpl();
    core::Validator::validateId(messageId, "field:messageId ");
    try {
        return impl->updateMessage(messageId, publicMeta, privateMeta, data);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::vector<std::string> ThreadApi::subscribeFor(const std::vector<std::string>& subscriptionQueries) {
    auto impl = getImpl();
    try {
        return impl->subscribeFor(subscriptionQueries);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void ThreadApi::unsubscribeFrom(const std::vector<std::string>& subscriptionIds) {
    auto impl = getImpl();
    try {
        return impl->unsubscribeFrom(subscriptionIds);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::string ThreadApi::buildSubscriptionQuery(EventType eventType, EventSelectorType selectorType, const std::string& selectorId) {
    auto impl = getImpl();
    try {
        return impl->buildSubscriptionQuery(eventType, selectorType, selectorId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

