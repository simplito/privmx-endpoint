/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/core/varinterface/ConnectionVarInterface.hpp"

#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/core/varinterface/VarInterfaceUtil.hpp"
#include "privmx/endpoint/core/varinterface/VarUserVerifierInterface.hpp"
using namespace privmx::endpoint::core;

std::map<ConnectionVarInterface::METHOD, Poco::Dynamic::Var (ConnectionVarInterface::*)(const Poco::Dynamic::Var&)>
    ConnectionVarInterface::methodMap = {{Connect, &ConnectionVarInterface::connect},
                                         {ConnectPublic, &ConnectionVarInterface::connectPublic},
                                         {GetConnectionId, &ConnectionVarInterface::getConnectionId},
                                         {ListContexts, &ConnectionVarInterface::listContexts},
                                         {Disconnect, &ConnectionVarInterface::disconnect},
                                         {GetContextUsers, &ConnectionVarInterface::getContextUsers},
                                         {SubscribeFor, &ConnectionVarInterface::subscribeFor},
                                         {UnsubscribeFrom, &ConnectionVarInterface::unsubscribeFrom},
                                         {BuildSubscriptionQuery, &ConnectionVarInterface::buildSubscriptionQuery}
                                        };

Poco::Dynamic::Var ConnectionVarInterface::connect(const Poco::Dynamic::Var& args) {
    auto argsArr = VarInterfaceUtil::validateAndExtractArray(args, 3, 4);
    auto userPrivKey = _deserializer.deserialize<std::string>(argsArr->get(0), "userPrivKey");
    auto solutionId = _deserializer.deserialize<std::string>(argsArr->get(1), "solutionId");
    auto platformUrl = _deserializer.deserialize<std::string>(argsArr->get(2), "platformUrl");
    auto verificationOptions = PKIVerificationOptions();
    if(argsArr->size() == 4) {
        verificationOptions = _deserializer.deserialize<PKIVerificationOptions>(argsArr->get(3), "verificationOptions");
    }
    _connection = Connection::connect(userPrivKey, solutionId, platformUrl, verificationOptions);
    return {};
}

Poco::Dynamic::Var ConnectionVarInterface::connectPublic(const Poco::Dynamic::Var& args) {
    auto argsArr = VarInterfaceUtil::validateAndExtractArray(args, 2, 3);
    auto solutionId = _deserializer.deserialize<std::string>(argsArr->get(0), "solutionId");
    auto platformUrl = _deserializer.deserialize<std::string>(argsArr->get(1), "platformUrl");
    auto verificationOptions = PKIVerificationOptions();
    if(args.size() >= 3) {
        verificationOptions = _deserializer.deserialize<PKIVerificationOptions>(argsArr->get(2), "verificationOptions");
    }
    _connection = Connection::connectPublic(solutionId, platformUrl, verificationOptions);
    return {};
}

Poco::Dynamic::Var ConnectionVarInterface::getConnectionId(const Poco::Dynamic::Var& args) {
    VarInterfaceUtil::validateAndExtractArray(args, 0);
    auto result = _connection.getConnectionId();
    return _serializer.serialize(result);
}

Poco::Dynamic::Var ConnectionVarInterface::listContexts(const Poco::Dynamic::Var& args) {
    auto argsArr = VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto pagingQuery = _deserializer.deserialize<PagingQuery>(argsArr->get(0), "pagingQuery");
    auto result = _connection.listContexts(pagingQuery);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var ConnectionVarInterface::disconnect(const Poco::Dynamic::Var& args) {
    VarInterfaceUtil::validateAndExtractArray(args, 0);
    _connection.disconnect();
    return {};
}

Poco::Dynamic::Var ConnectionVarInterface::getContextUsers(const Poco::Dynamic::Var& args) {
    auto argsArr = VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto contextId = _deserializer.deserialize<std::string>(argsArr->get(0), "contextId");
    auto result = _connection.getContextUsers(contextId);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var ConnectionVarInterface::setUserVerifier(const std::function<Poco::Dynamic::Var(const Poco::Dynamic::Var&)>& verifierCallback) {
    std::shared_ptr<VarUserVerifierInterface> verifier = std::make_shared<VarUserVerifierInterface>(verifierCallback, _deserializer, _serializer);
    _connection.setUserVerifier(verifier);
    return {};
}

Poco::Dynamic::Var ConnectionVarInterface::subscribeFor(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto subscriptionQueries = _deserializer.deserializeVector<std::string>(argsArr->get(0), "subscriptionQueries");
    auto result = _connection.subscribeFor(subscriptionQueries);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var ConnectionVarInterface::unsubscribeFrom(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto subscriptionIds = _deserializer.deserializeVector<std::string>(argsArr->get(0), "subscriptionIds");
    _connection.unsubscribeFrom(subscriptionIds);
    return {};
}

Poco::Dynamic::Var ConnectionVarInterface::buildSubscriptionQuery(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 3);
    auto eventType = _deserializer.deserialize<core::EventType>(argsArr->get(0), "eventType");
    auto selectorType = _deserializer.deserialize<core::EventSelectorType>(argsArr->get(1), "selectorType");
    auto selectorId = _deserializer.deserialize<std::string>(argsArr->get(2), "selectorId");
    auto result = _connection.buildSubscriptionQuery(eventType, selectorType, selectorId);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var ConnectionVarInterface::exec(METHOD method, const Poco::Dynamic::Var& args) {
    auto it = methodMap.find(method);
    if (it == methodMap.end()) {
        throw InvalidMethodException();
    }
    return (*this.*(it->second))(args);
}
