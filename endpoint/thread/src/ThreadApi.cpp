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
#include "privmx/endpoint/thread/ThreadVarSerializer.hpp"
#include "privmx/endpoint/thread/ThreadException.hpp"
#include "privmx/endpoint/thread/ThreadValidator.hpp"
#include "privmx/endpoint/core/EventVarSerializer.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::thread;

ThreadApi ThreadApi::create(core::Connection& connection) {
    try {
        std::shared_ptr<core::ConnectionImpl> connectionImpl = connection.getImpl();
        std::shared_ptr<ThreadApiImpl> impl(new ThreadApiImpl(
            connectionImpl->getGateway(),
            connectionImpl->getUserPrivKey(),
            connectionImpl->getKeyProvider(),
            connectionImpl->getHost(),
            connectionImpl->getEventMiddleware(),
            connectionImpl->getEventChannelManager(),
            connection
        ));
        return ThreadApi(impl);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

ThreadApi::ThreadApi(const std::shared_ptr<ThreadApiImpl>& impl) : _impl(impl) {}

void ThreadApi::validateEndpoint() {
    if(!_impl) throw NotInitializedException();
}

std::string ThreadApi::createThread(
    const std::string& contextId, 
    const std::vector<core::UserWithPubKey>& users, 
    const std::vector<core::UserWithPubKey>& managers,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const std::optional<core::ContainerPolicy>& policies
) {
    validateEndpoint();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    try {
        return _impl->createThread(contextId, users, managers, publicMeta, privateMeta, policies);
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
    validateEndpoint();
    try {
        _impl->updateThread(threadId, users, managers, publicMeta, privateMeta, version, force, forceGenerateNewKey, policies);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void ThreadApi::deleteThread(const std::string& threadId) {
    validateEndpoint();
    core::Validator::validateId(threadId, "field:threadId ");
    try {
        return _impl->deleteThread(threadId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

Thread ThreadApi::getThread(const std::string& threadId) {
    validateEndpoint();
    core::Validator::validateId(threadId, "field:threadId ");
    try {
        return _impl->getThread(threadId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

core::PagingList<Thread> ThreadApi::listThreads(const std::string& contextId, const core::PagingQuery& pagingQuery) {
    validateEndpoint();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validateClass<core::PagingQuery>(pagingQuery, "field:pagingQuery ");
    try {
        return _impl->listThreads(contextId, pagingQuery);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

Message ThreadApi::getMessage(const std::string& messageId) {
    validateEndpoint();
    core::Validator::validateId(messageId, "field:messageId ");
    try {
        return _impl->getMessage(messageId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

core::PagingList<Message> ThreadApi::listMessages(const std::string& threadId, const core::PagingQuery& pagingQuery) {
    validateEndpoint();
    core::Validator::validateId(threadId, "field:threadId ");
    core::StructValidator<core::PagingQuery>::validate(pagingQuery, "field:pagingQuery ");
    try {
        return _impl->listMessages(threadId, pagingQuery);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::string ThreadApi::sendMessage(const std::string& threadId, const core::Buffer& publicMeta, const core::Buffer& privateMeta, const core::Buffer& data) {
    validateEndpoint();
    core::Validator::validateId(threadId, "field:threadId ");
    try {
        return _impl->sendMessage(threadId, publicMeta, privateMeta, data);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void ThreadApi::deleteMessage(const std::string& messageId) {
    validateEndpoint();
    core::Validator::validateId(messageId, "field:messageId ");
    try {
        return _impl->deleteMessage(messageId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void ThreadApi::updateMessage(const std::string& messageId, const core::Buffer& publicMeta, const core::Buffer& privateMeta, const core::Buffer& data) {
    validateEndpoint();
    core::Validator::validateId(messageId, "field:messageId ");
    try {
        return _impl->updateMessage(messageId, publicMeta, privateMeta, data);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void ThreadApi::subscribeForThreadEvents() {
    validateEndpoint();
    try {
        return _impl->subscribeForThreadEvents();
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void ThreadApi::unsubscribeFromThreadEvents() {
    validateEndpoint();
    try {
        return _impl->unsubscribeFromThreadEvents();
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void ThreadApi::subscribeForMessageEvents(const std::string& threadId) {
    validateEndpoint();
    core::Validator::validateId(threadId, "field:threadId ");
    try {
        return _impl->subscribeForMessageEvents(threadId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void ThreadApi::unsubscribeFromMessageEvents(const std::string& threadId) {
    validateEndpoint();
    core::Validator::validateId(threadId, "field:threadId ");
    try {
        return _impl->unsubscribeFromMessageEvents(threadId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}
