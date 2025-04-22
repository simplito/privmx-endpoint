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

using namespace privmx::endpoint::core;

std::map<ConnectionVarInterface::METHOD, Poco::Dynamic::Var (ConnectionVarInterface::*)(const Poco::Dynamic::Var&)>
    ConnectionVarInterface::methodMap = {{Connect, &ConnectionVarInterface::connect},
                                         {ConnectPublic, &ConnectionVarInterface::connectPublic},
                                         {GetConnectionId, &ConnectionVarInterface::getConnectionId},
                                         {ListContexts, &ConnectionVarInterface::listContexts},
                                         {Disconnect, &ConnectionVarInterface::disconnect},
                                         {GetContextUsers, &ConnectionVarInterface::getContextUsers}};

Poco::Dynamic::Var ConnectionVarInterface::connect(const Poco::Dynamic::Var& args) {
    auto argsArr = VarInterfaceUtil::validateAndExtractArray(args, 3, 4);
    auto userPrivKey = _deserializer.deserialize<std::string>(argsArr->get(0), "userPrivKey");
    auto solutionId = _deserializer.deserialize<std::string>(argsArr->get(1), "solutionId");
    auto platformUrl = _deserializer.deserialize<std::string>(argsArr->get(2), "platformUrl");
    auto verificationOptions = VerificationOptions();
    if(args.size() >= 4) {
        verificationOptions = _deserializer.deserialize<VerificationOptions>(argsArr->get(3), "verificationOptions");
    }
    _connection = Connection::connect(userPrivKey, solutionId, platformUrl, verificationOptions);
    return {};
}

Poco::Dynamic::Var ConnectionVarInterface::connectPublic(const Poco::Dynamic::Var& args) {
    auto argsArr = VarInterfaceUtil::validateAndExtractArray(args, 2, 3);
    auto solutionId = _deserializer.deserialize<std::string>(argsArr->get(0), "solutionId");
    auto platformUrl = _deserializer.deserialize<std::string>(argsArr->get(1), "platformUrl");
    auto verificationOptions = VerificationOptions();
    if(args.size() >= 3) {
        verificationOptions = _deserializer.deserialize<VerificationOptions>(argsArr->get(2), "verificationOptions");
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

Poco::Dynamic::Var ConnectionVarInterface::exec(METHOD method, const Poco::Dynamic::Var& args) {
    auto it = methodMap.find(method);
    if (it == methodMap.end()) {
        throw InvalidMethodException();
    }
    return (*this.*(it->second))(args);
}
