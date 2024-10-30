#include "privmx/endpoint/core/varinterface/ConnectionVarInterface.hpp"

#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/core/varinterface/VarInterfaceUtil.hpp"

using namespace privmx::endpoint::core;

std::map<ConnectionVarInterface::METHOD, Poco::Dynamic::Var (ConnectionVarInterface::*)(const Poco::Dynamic::Var&)>
    ConnectionVarInterface::methodMap = {{Connect, &ConnectionVarInterface::connect},
                                         {ConnectPublic, &ConnectionVarInterface::connectPublic},
                                         {GetConnectionId, &ConnectionVarInterface::getConnectionId},
                                         {ListContexts, &ConnectionVarInterface::listContexts},
                                         {Disconnect, &ConnectionVarInterface::disconnect}};

Poco::Dynamic::Var ConnectionVarInterface::connect(const Poco::Dynamic::Var& args) {
    auto argsArr = VarInterfaceUtil::validateAndExtractArray(args, 3);
    auto userPrivKey = _deserializer.deserialize<std::string>(argsArr->get(0), "userPrivKey");
    auto solutionId = _deserializer.deserialize<std::string>(argsArr->get(1), "solutionId");
    auto platformUrl = _deserializer.deserialize<std::string>(argsArr->get(2), "platformUrl");
    _connection = Connection::platformConnect(userPrivKey, solutionId, platformUrl);
    return {};
}

Poco::Dynamic::Var ConnectionVarInterface::connectPublic(const Poco::Dynamic::Var& args) {
    auto argsArr = VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto solutionId = _deserializer.deserialize<std::string>(argsArr->get(0), "solutionId");
    auto platformUrl = _deserializer.deserialize<std::string>(argsArr->get(1), "platformUrl");
    _connection = Connection::platformConnectPublic(solutionId, platformUrl);
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

Poco::Dynamic::Var ConnectionVarInterface::exec(METHOD method, const Poco::Dynamic::Var& args) {
    auto it = methodMap.find(method);
    if (it == methodMap.end()) {
        throw InvalidMethodException();
    }
    return (*this.*(it->second))(args);
}
