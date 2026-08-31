/*
PrivMX Endpoint.
Copyright © 2026 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/lock/varinterface/LockApiVarInterface.hpp"

#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/core/varinterface/VarInterfaceUtil.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::lock;

std::map<LockApiVarInterface::METHOD, Poco::Dynamic::Var (LockApiVarInterface::*)(const Poco::Dynamic::Var&)>
    LockApiVarInterface::methodMap = {
        {Create, &LockApiVarInterface::create},
        {Lock, &LockApiVarInterface::lock},
        {Unlock, &LockApiVarInterface::unlock},
        {CheckReservedLock, &LockApiVarInterface::checkReservedLock},
};

Poco::Dynamic::Var LockApiVarInterface::create(const Poco::Dynamic::Var& args) {
    core::VarInterfaceUtil::validateAndExtractArray(args, 0);
    _lockApi = LockApi::create(_connection);
    return {};
}

Poco::Dynamic::Var LockApiVarInterface::lock(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 3);
    auto resourceId = _deserializer.deserialize<std::string>(argsArr->get(0), "resourceId");
    auto uuid = _deserializer.deserialize<std::string>(argsArr->get(1), "uuid");
    auto lockLevel = _deserializer.deserialize<lock::LockLevel>(argsArr->get(2), "lockLevel");
    auto result = _lockApi.lock(resourceId, uuid, lockLevel);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var LockApiVarInterface::unlock(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 3);
    auto resourceId = _deserializer.deserialize<std::string>(argsArr->get(0), "resourceId");
    auto uuid = _deserializer.deserialize<std::string>(argsArr->get(1), "uuid");
    auto lockLevel = _deserializer.deserialize<lock::LockLevel>(argsArr->get(2), "lockLevel");
    auto result = _lockApi.unlock(resourceId, uuid, lockLevel);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var LockApiVarInterface::checkReservedLock(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto resourceId = _deserializer.deserialize<std::string>(argsArr->get(0), "resourceId");
    auto uuid = _deserializer.deserialize<std::string>(argsArr->get(1), "uuid");
    auto result = _lockApi.checkReservedLock(resourceId, uuid);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var LockApiVarInterface::exec(METHOD method, const Poco::Dynamic::Var& args) {
    auto it = methodMap.find(method);
    if (it == methodMap.end()) {
        throw core::InvalidMethodException();
    }
    return (*this.*(it->second))(args);
}
