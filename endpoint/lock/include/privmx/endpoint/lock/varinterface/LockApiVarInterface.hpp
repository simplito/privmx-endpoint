/*
PrivMX Endpoint.
Copyright © 2026 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_LOCK_LOCKAPIVARINTERFACE_HPP_
#define _PRIVMXLIB_ENDPOINT_LOCK_LOCKAPIVARINTERFACE_HPP_

#include <map>

#include <Poco/Dynamic/Var.h>

#include "privmx/endpoint/lock/LockApi.hpp"
#include "privmx/endpoint/lock/VarDeserializer.hpp"
#include "privmx/endpoint/lock/VarSerializer.hpp"

namespace privmx {
namespace endpoint {
namespace lock {

class LockApiVarInterface {
public:
    enum METHOD {
        Create = 0,
        Lock = 1,
        Unlock = 2,
        CheckReservedLock = 3,
    };

    LockApiVarInterface(core::Connection connection, const core::VarSerializer& serializer)
        : _connection(std::move(connection)), _serializer(serializer) {}

    Poco::Dynamic::Var create(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var lock(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var unlock(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var checkReservedLock(const Poco::Dynamic::Var& args);

    Poco::Dynamic::Var exec(METHOD method, const Poco::Dynamic::Var& args);

    LockApi getApi() const { return _lockApi; }

private:
    static std::map<METHOD, Poco::Dynamic::Var (LockApiVarInterface::*)(const Poco::Dynamic::Var&)> methodMap;

    core::Connection _connection;
    LockApi _lockApi;
    core::VarDeserializer _deserializer;
    core::VarSerializer _serializer;
};

} // namespace lock
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_LOCK_LOCKAPIVARINTERFACE_HPP_
