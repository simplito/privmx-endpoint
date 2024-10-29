#ifndef _PRIVMXLIB_ENDPOINT_CORE_EVENTQUEUEVARINTERFACE_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_EVENTQUEUEVARINTERFACE_HPP_

#include <Poco/Dynamic/Var.h>

#include "privmx/endpoint/core/EventQueue.hpp"
#include "privmx/endpoint/core/VarSerializer.hpp"

namespace privmx {
namespace endpoint {
namespace core {

class EventQueueVarInterface {
public:
    enum METHOD { WaitEvent = 0, GetEvent = 1, EmitBreakEvent = 2 };

    EventQueueVarInterface(EventQueue eventQueue, const VarSerializer& serializer)
        : _eventQueue(std::move(eventQueue)), _serializer(serializer) {}

    Poco::Dynamic::Var waitEvent(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var getEvent(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var emitBreakEvent(const Poco::Dynamic::Var& args);

    Poco::Dynamic::Var exec(METHOD method, const Poco::Dynamic::Var& args);

private:
    static std::map<METHOD, Poco::Dynamic::Var (EventQueueVarInterface::*)(const Poco::Dynamic::Var&)> methodMap;

    EventQueue _eventQueue;
    VarSerializer _serializer;
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_EVENTQUEUEVARINTERFACE_HPP_
