#ifndef _PRIVMXLIB_ENDPOINT_CORE_EVENTQUEUE_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_EVENTQUEUE_HPP_

#include <memory>
#include <optional>

#include "privmx/endpoint/core/Events.hpp"

namespace privmx {
namespace endpoint {
namespace core {

class EventQueueImpl;

/**
 * 'EventQueue' is a singleton class representing a queue for storing events.
 */
class EventQueue {
public:

    /**
     * Gets the EventQueue instance.
     *
     * @return EventQueue object
     */
    static EventQueue getInstance();

    /**
     * Puts the break event on the events queue.
     * 
     * You can use it to break the `waitEvent` loop.
     */
    void emitBreakEvent();

    /**
     * Starts a loop waiting for an Event.
     * 
     * @return EventHolder object
     */
    EventHolder waitEvent();

    /**
     * Gets the first event from the events queue.
     * 
     * @return EventHolder object (optional)
     */
    std::optional<EventHolder> getEvent();

private:
    EventQueue() {};
    EventQueue(std::shared_ptr<EventQueueImpl> impl) : _impl(impl) {};
    std::shared_ptr<EventQueueImpl> _impl;
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_EVENTQUEUE_HPP_
