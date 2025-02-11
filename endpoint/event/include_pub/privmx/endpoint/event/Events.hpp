#ifndef _PRIVMXLIB_ENDPOINT_EVENT_EVENTS_HPP_
#define _PRIVMXLIB_ENDPOINT_EVENT_EVENTS_HPP_

#include "privmx/endpoint/core/Events.hpp"
#include "privmx/endpoint/core/Types.hpp"

namespace privmx {
namespace endpoint {
namespace event {

/**
 * Holds data of event that arrives when custom context event is emitted.
 */
struct CustomContextEvent : public core::Event {

    /**
     * Event constructor
     */
    CustomContextEvent() : core::Event("customContext") {}

    /**
     * Get Event as JSON string
     * 
     * @return JSON string
     */
    std::string toJSON() const override;

    /**
     * //doc-gen:ignore
     */
    std::shared_ptr<core::SerializedEvent> serialize() const override;
    
    /**
     * id of context from which it was sent
     */
    std::string contextId;
    /**
     * id of user which sent it
     */
    std::string userId;
    /**
     * event data
     */
    core::Buffer data;
};

/**
 * 'Events' provides the helpers methods for module's events management.
 */
class Events {
public:

    /**
     * Checks whether event held in the 'EventHolder' is an 'CustomContextEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'CustomContextEvent', else otherwise
     */
    static bool isCustomContextEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'CustomContextEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'CustomContextEvent' object
     */
    static CustomContextEvent extractCustomContextEvent(const core::EventHolder& eventHolder);

};

}  // event
}  // endpoint
}  // privmx

#endif // _PRIVMXLIB_ENDPOINT_EVENT_EVENTS_HPP_