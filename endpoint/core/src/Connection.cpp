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
#include "privmx/endpoint/core/JsonSerializer.hpp"
#include "privmx/endpoint/core/Validator.hpp"
#include "privmx/endpoint/core/VarSerializer.hpp"
#include <cstdint>
#include <privmx/utils/Logger.hpp>

using namespace privmx::endpoint::core;

Connection::Connection() {};
Connection::Connection(const Connection& obj) : BaseApiClass(obj), _connectionId(obj._connectionId) {};
Connection& Connection::operator=(const Connection& obj) {
    this->BaseApiClass::operator=(obj);
    this->_connectionId = obj._connectionId;
    return *this;
};
Connection::Connection(Connection&& obj) : BaseApiClass(std::move(obj)), _connectionId(obj._connectionId) {};
Connection::~Connection() {}

Connection Connection::connect(
    const std::string& userPrivKey,
    const std::string& solutionId,
    const std::string& platformUrl,
    const PKIVerificationOptions& verificationOptions
) {
    Validator::validatePrivKeyWIF(userPrivKey, "field:userPrivKey ");
    Validator::validateId(solutionId, "field:solutionId ");
    Validator::validateClass<PKIVerificationOptions>(verificationOptions, "field:verificationOptions ");
    std::shared_ptr<ConnectionImpl> impl(new ConnectionImpl());
    impl->connect(userPrivKey, solutionId, platformUrl, verificationOptions);
    return Connection(impl);
}

Connection Connection::connectPublic(
    const std::string& solutionId,
    const std::string& platformUrl,
    const PKIVerificationOptions& verificationOptions
) {
    Validator::validateClass<PKIVerificationOptions>(verificationOptions, "field:verificationOptions ");
    std::shared_ptr<ConnectionImpl> impl(new ConnectionImpl());
    impl->connectPublic(solutionId, platformUrl, verificationOptions);
    return Connection(impl);
}

Connection::Connection(const std::shared_ptr<ConnectionImpl>& impl)
    : BaseApiClass(impl), _connectionId(std::move(impl->getConnectionId())) {}

void Connection::assertGateway(const std::shared_ptr<ConnectionImpl>& impl) {
    if (impl->getGateway().isNull())
        throw core::NotConnectedException();
}

void Connection::assertConnection(const std::shared_ptr<ConnectionImpl>& impl) {
    assertGateway(impl);
    if (!impl->isConnected())
        throw core::NotConnectedException();
}

int64_t Connection::getConnectionId() {
    if (_connectionId.has_value()) {
        return _connectionId.value();
    } else {
        _connectionId = getImpl()->getConnectionId();
        return _connectionId.value();
    }
}

PagingList<Context> Connection::listContexts(const PagingQuery& pagingQuery) {
    auto impl = getImpl();
    assertConnection(impl);
    core::Validator::validatePagingQuery(pagingQuery, {}, "field:pagingQuery ");
    return impl->listContexts(pagingQuery);
}

PagingList<UserInfo> Connection::listContextUsers(const std::string& contextId, const PagingQuery& pagingQuery) {
    auto impl = getImpl();
    assertConnection(impl);
    Validator::validateId(contextId, "field:contextId ");
    core::Validator::validatePagingQuery(pagingQuery, {}, "field:pagingQuery ");
    return impl->listContextUsers(contextId, pagingQuery);
}

void Connection::setUserVerifier(std::shared_ptr<UserVerifierInterface> verifier) {
    auto impl = getImpl();
    impl->setUserVerifier(verifier);
}

std::vector<std::string> Connection::subscribeFor(const std::vector<std::string>& subscriptionQueries) {
    auto impl = getImpl();
    assertConnection(impl);
    return impl->subscribeFor(subscriptionQueries);
}

void Connection::unsubscribeFrom(const std::vector<std::string>& subscriptionIds) {
    auto impl = getImpl();
    assertConnection(impl);
    return impl->unsubscribeFrom(subscriptionIds);
}

std::string Connection::buildSubscriptionQuery(
    EventType eventType,
    EventSelectorType selectorType,
    const std::string& selectorId
) {
    auto impl = getImpl();
    assertConnection(impl);
    return impl->buildSubscriptionQuery(eventType, selectorType, selectorId);
}

void Connection::disconnect() {
    auto impl = getImpl();
    assertGateway(impl);
    impl->disconnect();
}
