/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_EVENT_EVENTSAPIVARINTERFACE_HPP_
#define _PRIVMXLIB_ENDPOINT_EVENT_EVENTSAPIVARINTERFACE_HPP_

#include <Poco/Dynamic/Var.h>

#include "privmx/endpoint/event/EventApi.hpp"
#include "privmx/endpoint/event/VarSerializer.hpp"
#include "privmx/endpoint/event/VarDeserializer.hpp"
#include <privmx/endpoint/core/VarDeserializer.hpp>
#include <privmx/endpoint/event/VarDeserializer.hpp>

namespace privmx {
namespace endpoint {
namespace event {

class EventApiVarInterface {
public:
    enum METHOD {
        Create = 0,
        EmitEvent = 1,
        SubscribeForCustomEvents = 2,
        UnsubscribeFromCustomEvents = 3,
        SubscribeFor = 4,
        UnsubscribeFrom = 5,
        BuildSubscriptionQuery = 6,
    };

    EventApiVarInterface(core::Connection connection, const core::VarSerializer& serializer)
        : _connection(std::move(connection)), _serializer(serializer) {}

    Poco::Dynamic::Var create(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var emitEvent(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var subscribeForCustomEvents(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var unsubscribeFromCustomEvents(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var subscribeFor(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var unsubscribeFrom(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var buildSubscriptionQuery(const Poco::Dynamic::Var& args);

    Poco::Dynamic::Var exec(METHOD method, const Poco::Dynamic::Var& args);

    EventApi getApi() const { return _eventApi; }

private:
    static std::map<METHOD, Poco::Dynamic::Var (EventApiVarInterface::*)(const Poco::Dynamic::Var&)> methodMap;

    core::Connection _connection;
    EventApi _eventApi;
    core::VarSerializer _serializer;
    core::VarDeserializer _deserializer;
};

}  // namespace event
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_EVENT_EVENTSAPIVARINTERFACE_HPP_
