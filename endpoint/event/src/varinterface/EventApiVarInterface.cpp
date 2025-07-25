/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/event/varinterface/EventApiVarInterface.hpp"
#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/core/varinterface/VarInterfaceUtil.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::event;

std::map<EventApiVarInterface::METHOD, Poco::Dynamic::Var (EventApiVarInterface::*)(const Poco::Dynamic::Var&)>
    EventApiVarInterface::methodMap = {{Create, &EventApiVarInterface::create},
                                       {EmitEvent, &EventApiVarInterface::emitEvent},
                                       {SubscribeForCustomEvents, &EventApiVarInterface::subscribeForCustomEvents},
                                       {UnsubscribeFromCustomEvents, &EventApiVarInterface::unsubscribeFromCustomEvents},
                                       {SubscribeFor, &EventApiVarInterface::subscribeFor},
                                       {UnsubscribeFrom, &EventApiVarInterface::unsubscribeFrom},
                                       {BuildSubscriptionQuery, &EventApiVarInterface::buildSubscriptionQuery}};

Poco::Dynamic::Var EventApiVarInterface::create(const Poco::Dynamic::Var& args) {
    core::VarInterfaceUtil::validateAndExtractArray(args, 0);
    _eventApi = EventApi::create(_connection);
    return {};
}

Poco::Dynamic::Var EventApiVarInterface::emitEvent(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 4);
    auto contextId = _deserializer.deserialize<std::string>(argsArr->get(0), "contextId");
    auto users = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(1), "users");
    auto channelName = _deserializer.deserialize<std::string>(argsArr->get(2), "channelName");
    auto eventData = _deserializer.deserialize<core::Buffer>(argsArr->get(3), "eventData");
    _eventApi.emitEvent(contextId, users, channelName, eventData);
    return {};
}


Poco::Dynamic::Var EventApiVarInterface::subscribeForCustomEvents(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto contextId = _deserializer.deserialize<std::string>(argsArr->get(0), "contextId");
    auto channelName = _deserializer.deserialize<std::string>(argsArr->get(1), "channelName");
    _eventApi.subscribeForCustomEvents(contextId, channelName);
    return {};
}

Poco::Dynamic::Var EventApiVarInterface::unsubscribeFromCustomEvents(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto contextId = _deserializer.deserialize<std::string>(argsArr->get(0), "contextId");
    auto channelName = _deserializer.deserialize<std::string>(argsArr->get(1), "channelName");
    _eventApi.unsubscribeFromCustomEvents(contextId, channelName);
    return {};
}

Poco::Dynamic::Var EventApiVarInterface::subscribeFor(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto subscriptionQueries = _deserializer.deserializeVector<std::string>(argsArr->get(0), "subscriptionQueries");
    auto result = _eventApi.subscribeFor(subscriptionQueries);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var EventApiVarInterface::unsubscribeFrom(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto subscriptionIds = _deserializer.deserializeVector<std::string>(argsArr->get(0), "subscriptionIds");
    _eventApi.unsubscribeFrom(subscriptionIds);
    return {};
}

Poco::Dynamic::Var EventApiVarInterface::buildSubscriptionQuery(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 3);
    auto channelName = _deserializer.deserialize<std::string>(argsArr->get(0), "channelName");
    auto selectorType = _deserializer.deserialize<event::EventSelectorType>(argsArr->get(1), "selectorType");
    auto selectorId = _deserializer.deserialize<std::string>(argsArr->get(2), "selectorId");
    auto result = _eventApi.buildSubscriptionQuery(channelName, selectorType, selectorId);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var EventApiVarInterface::exec(METHOD method, const Poco::Dynamic::Var& args) {
    auto it = methodMap.find(method);
    if (it == methodMap.end()) {
        throw core::InvalidMethodException();
    }
    return (*this.*(it->second))(args);
}
