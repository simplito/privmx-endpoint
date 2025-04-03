/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_EVENTQUEUEVARINTERFACE_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_EVENTQUEUEVARINTERFACE_HPP_

#include <Poco/Dynamic/Var.h>

#include "privmx/endpoint/core/c_api.h"
#include "privmx/endpoint/core/EventQueue.hpp"
#include "privmx/endpoint/core/VarSerializer.hpp"

namespace privmx {
namespace endpoint {
namespace core {

class EventQueueVarInterface {
public:
    EventQueueVarInterface(EventQueue eventQueue, const VarSerializer& serializer)
        : _eventQueue(std::move(eventQueue)), _serializer(serializer) {}

    Poco::Dynamic::Var waitEvent(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var getEvent(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var emitBreakEvent(const Poco::Dynamic::Var& args);

    Poco::Dynamic::Var exec(privmx_EventQueue_Method method, const Poco::Dynamic::Var& args);

private:
    static std::map<privmx_EventQueue_Method, Poco::Dynamic::Var (EventQueueVarInterface::*)(const Poco::Dynamic::Var&)> methodMap;

    EventQueue _eventQueue;
    VarSerializer _serializer;
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_EVENTQUEUEVARINTERFACE_HPP_
