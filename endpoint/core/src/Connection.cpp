/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/core/Connection.hpp"

#include "privmx/endpoint/core/ConnectionImpl.hpp"
#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/core/EventVarSerializer.hpp"
#include "privmx/endpoint/core/ExceptionConverter.hpp"
#include "privmx/endpoint/core/JsonSerializer.hpp"
#include "privmx/endpoint/core/Validator.hpp"
#include "privmx/endpoint/core/VarSerializer.hpp"

using namespace privmx::endpoint::core;

Connection Connection::connect(const std::string& userPrivKey, const std::string& solutionId,
                                const std::string& platformUrl, const PKIVerificationOptions& verificationOptions) {
    Validator::validatePrivKeyWIF(userPrivKey, "field:userPrivKey ");
    Validator::validateId(solutionId, "field:solutionId ");
    Validator::validateClass<PKIVerificationOptions>(verificationOptions, "field:verificationOptions ");
    try {
        std::shared_ptr<ConnectionImpl> impl(new ConnectionImpl());
        impl->connect(userPrivKey, solutionId, platformUrl, verificationOptions);
        return Connection(impl);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

Connection Connection::connectPublic(const std::string& solutionId, const std::string& platformUrl, 
                                        const PKIVerificationOptions& verificationOptions) {
    Validator::validateClass<PKIVerificationOptions>(verificationOptions, "field:verificationOptions ");
    try {
        std::shared_ptr<ConnectionImpl> impl(new ConnectionImpl());
        impl->connectPublic(solutionId, platformUrl, verificationOptions);
        return Connection(impl);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

Connection::Connection(const std::shared_ptr<ConnectionImpl>& impl) : _impl(impl) {}

void Connection::validateEndpoint() {
    if (!_impl) throw core::NotInitializedException();
    if (_impl->getGateway().isNull()) throw core::NotInitializedException();
}

int64_t Connection::getConnectionId() {
    if (!_impl) throw core::NotInitializedException();
    try {
        return _impl->getConnectionId();
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

PagingList<Context> Connection::listContexts(const PagingQuery& pagingQuery) {
    validateEndpoint();
    core::Validator::validatePagingQuery(pagingQuery, {}, "field:pagingQuery ");
    try {
        return _impl->listContexts(pagingQuery);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

PagingList<UserInfo> Connection::listContextUsers(const std::string& contextId, const PagingQuery& pagingQuery) {
    validateEndpoint();
    Validator::validateId(contextId, "field:contextId ");
    core::Validator::validatePagingQuery(pagingQuery, {}, "field:pagingQuery ");
    try {
        return _impl->listContextUsers(contextId, pagingQuery);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void Connection::setUserVerifier(std::shared_ptr<UserVerifierInterface> verifier) {
    _impl->setUserVerifier(verifier);
}

std::vector<std::string> Connection::subscribeFor(const std::vector<std::string>& subscriptionQueries) {
    validateEndpoint();
    try {
        return _impl->subscribeFor(subscriptionQueries);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void Connection::unsubscribeFrom(const std::vector<std::string>& subscriptionIds) {
    validateEndpoint();
    try {
        return _impl->unsubscribeFrom(subscriptionIds);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::string Connection::buildSubscriptionQuery(EventType eventType, EventSelectorType selectorType, const std::string& selectorId) {
    validateEndpoint();
    try {
        return _impl->buildSubscriptionQuery(eventType, selectorType, selectorId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void Connection::disconnect() {
    validateEndpoint();
    try {
        _impl->disconnect();
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}
