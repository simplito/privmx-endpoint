/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/core/Connection.hpp"
#include <cstdint>
#include "privmx/endpoint/core/ConnectionImpl.hpp"
#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/core/EventVarSerializer.hpp"
#include "privmx/endpoint/core/ExceptionConverter.hpp"
#include "privmx/endpoint/core/JsonSerializer.hpp"
#include "privmx/endpoint/core/Validator.hpp"
#include "privmx/endpoint/core/VarSerializer.hpp"
#include <privmx/utils/Logger.hpp>

using namespace privmx::endpoint::core;

Connection::Connection() {
};
Connection::Connection(const Connection& obj): _impl(obj._impl), _connectionId(obj._connectionId) {
    attachToImplIfPossible();
};
Connection& Connection::operator=(const Connection& obj) {
    this->_impl = obj._impl;
    this->_connectionId = obj._connectionId;
    this->attachToImplIfPossible();
    return *this;
};
Connection::Connection(Connection&& obj): _impl(obj._impl), _connectionId(obj._connectionId) {
    attachToImplIfPossible();
};
Connection::~Connection() {
    detachFromImplIfPossible();
}

Connection Connection::connect(const std::string& userPrivKey, const std::string& solutionId,
                                const std::string& platformUrl, const PKIVerificationOptions& verificationOptions) {
    Validator::validatePrivKeyWIF(userPrivKey, "field:userPrivKey ");
    Validator::validateId(solutionId, "field:solutionId ");
    Validator::validateClass<PKIVerificationOptions>(verificationOptions, "field:verificationOptions ");
    try {
        std::shared_ptr<ConnectionImpl> impl(new ConnectionImpl());
        impl->connect(impl, userPrivKey, solutionId, platformUrl, verificationOptions);
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
        impl->connectPublic(impl, solutionId, platformUrl, verificationOptions);
        return Connection(impl);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

Connection::Connection(const std::shared_ptr<ConnectionImpl>& impl) : _impl(impl), _connectionId(impl->getConnectionId()) {}

std::shared_ptr<ConnectionImpl> Connection::getImpl() const { 
    auto impl = _impl.lock();
    if(!impl) throw NotInitializedException();
    return impl; 
}

void Connection::assertConnection(const std::shared_ptr<ConnectionImpl>& impl) {
    if(impl->getGateway().isNull()) throw core::NotInitializedException();
}

void Connection::attachToImplIfPossible() {
    if(!_impl.expired()) {
        auto impl = _impl.lock();
        if(impl) {
            impl->attach();
        }
    }
};

void Connection::detachFromImplIfPossible() {
    if(!_impl.expired()) {
        auto impl = _impl.lock();
        if(impl) {
            impl->detach();
        }
    }
};

int64_t Connection::getConnectionId() {
    if(_connectionId.has_value()) {
        return _connectionId.value();
    } else {
        auto impl = getImpl();
        try {
            _connectionId = impl->getConnectionId();
            return _connectionId.value();
        } catch (const privmx::utils::PrivmxException& e) {
            core::ExceptionConverter::rethrowAsCoreException(e);
            throw core::Exception("ExceptionConverter rethrow error");
        }
    }
}

PagingList<Context> Connection::listContexts(const PagingQuery& pagingQuery) {
    auto impl = getImpl();
    assertConnection(impl);
    core::Validator::validatePagingQuery(pagingQuery, {}, "field:pagingQuery ");
    try {
        return impl->listContexts(pagingQuery);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

PagingList<UserInfo> Connection::listContextUsers(const std::string& contextId, const PagingQuery& pagingQuery) {
    auto impl = getImpl();
    assertConnection(impl);
    Validator::validateId(contextId, "field:contextId ");
    core::Validator::validatePagingQuery(pagingQuery, {}, "field:pagingQuery ");
    try {
        return impl->listContextUsers(contextId, pagingQuery);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void Connection::setUserVerifier(std::shared_ptr<UserVerifierInterface> verifier) {
    auto impl = getImpl();
    impl->setUserVerifier(verifier);
}

std::vector<std::string> Connection::subscribeFor(const std::vector<std::string>& subscriptionQueries) {
    auto impl = getImpl();
    assertConnection(impl);
    try {
        return impl->subscribeFor(subscriptionQueries);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void Connection::unsubscribeFrom(const std::vector<std::string>& subscriptionIds) {
    auto impl = getImpl();
    assertConnection(impl);
    try {
        return impl->unsubscribeFrom(subscriptionIds);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::string Connection::buildSubscriptionQuery(EventType eventType, EventSelectorType selectorType, const std::string& selectorId) {
    auto impl = getImpl();
    assertConnection(impl);
    try {
        return impl->buildSubscriptionQuery(eventType, selectorType, selectorId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void Connection::disconnect() {
    auto impl = getImpl();
    assertConnection(impl);
    try {
        impl->disconnect();
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}
