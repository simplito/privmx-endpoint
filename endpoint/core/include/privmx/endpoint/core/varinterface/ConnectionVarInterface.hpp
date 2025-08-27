/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_CONNECTIONVARINTERFACE_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_CONNECTIONVARINTERFACE_HPP_

#include <Poco/Dynamic/Var.h>

#include "privmx/endpoint/core/Connection.hpp"
#include "privmx/endpoint/core/VarDeserializer.hpp"
#include "privmx/endpoint/core/VarSerializer.hpp"

namespace privmx {
namespace endpoint {
namespace core {

class ConnectionVarInterface {
public:
    enum METHOD {
        Connect = 0,
        ConnectPublic = 1,
        GetConnectionId = 2,
        ListContexts = 3,
        Disconnect = 4,
        GetContextUsers = 5,
        SetUserVerifier = 6,
        SubscribeFor = 7,
        UnsubscribeFrom = 8,
        BuildSubscriptionQuery = 9,
    };
    

    ConnectionVarInterface(const core::VarSerializer& serializer)
        : _serializer(serializer) {}

    Poco::Dynamic::Var connect(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var connectPublic(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var getConnectionId(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var listContexts(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var disconnect(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var getContextUsers(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var setUserVerifier(const std::function<Poco::Dynamic::Var(const Poco::Dynamic::Var&)>& verifierCallback);
    Poco::Dynamic::Var subscribeFor(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var unsubscribeFrom(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var buildSubscriptionQuery(const Poco::Dynamic::Var& args);

    Poco::Dynamic::Var exec(METHOD method, const Poco::Dynamic::Var& args);

    Connection getApi() const { return _connection; }

private:
    static std::map<METHOD, Poco::Dynamic::Var (ConnectionVarInterface::*)(const Poco::Dynamic::Var&)> methodMap;

    Connection _connection;
    core::VarDeserializer _deserializer;
    core::VarSerializer _serializer;
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_CONNECTIONVARINTERFACE_HPP_
