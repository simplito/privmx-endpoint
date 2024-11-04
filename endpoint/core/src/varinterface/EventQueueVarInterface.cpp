/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/core/varinterface/EventQueueVarInterface.hpp"

#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/core/EventVarSerializer.hpp"
#include "privmx/endpoint/core/varinterface/VarInterfaceUtil.hpp"

using namespace privmx::endpoint::core;

std::map<EventQueueVarInterface::METHOD, Poco::Dynamic::Var (EventQueueVarInterface::*)(const Poco::Dynamic::Var&)>
    EventQueueVarInterface::methodMap = {{WaitEvent, &EventQueueVarInterface::waitEvent},
                                         {GetEvent, &EventQueueVarInterface::getEvent},
                                         {EmitBreakEvent, &EventQueueVarInterface::emitBreakEvent}};

Poco::Dynamic::Var EventQueueVarInterface::waitEvent(const Poco::Dynamic::Var& args) {
    VarInterfaceUtil::validateAndExtractArray(args, 0);
    auto eventHolder = _eventQueue.waitEvent();
    auto serialized = eventHolder.get()->serialize();
    auto result = serialized->value;
    return result;
}

Poco::Dynamic::Var EventQueueVarInterface::getEvent(const Poco::Dynamic::Var& args) {
    VarInterfaceUtil::validateAndExtractArray(args, 0);
    auto eventHolder = _eventQueue.getEvent();
    if (eventHolder.has_value()) {
        auto serialized = eventHolder.value().get()->serialize();
        auto result = serialized->value;
        return result;
    }
    return {};
}

Poco::Dynamic::Var EventQueueVarInterface::emitBreakEvent(const Poco::Dynamic::Var& args) {
    VarInterfaceUtil::validateAndExtractArray(args, 0);
    _eventQueue.emitBreakEvent();
    return {};
}

Poco::Dynamic::Var EventQueueVarInterface::exec(METHOD method, const Poco::Dynamic::Var& args) {
    auto it = methodMap.find(method);
    if (it == methodMap.end()) {
        throw InvalidMethodException();
    }
    return (*this.*(it->second))(args);
}
