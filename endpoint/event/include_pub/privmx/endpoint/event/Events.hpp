#ifndef _PRIVMXLIB_ENDPOINT_EVENT_EVENTS_HPP_
#define _PRIVMXLIB_ENDPOINT_EVENT_EVENTS_HPP_

#include "privmx/endpoint/core/Events.hpp"
#include "privmx/endpoint/core/Types.hpp"

namespace privmx {
namespace endpoint {
namespace event {

/**
 * Holds information of `InboxEntryDeleted` event data.
 */
struct ContextCustomEventData {
    /**
     * Context ID
     */
    std::string contextId;
    /**
     * User ID (event's sender)
     */
    std::string userId;
    /**
     * Event's actual payload
     */
    core::Buffer payload;
    /**
     * Retrieval and decryption status code
     */
    int64_t statusCode;
    /**
     * Version of the event data structure and how it is encoded/encrypted
     */
    int64_t schemaVersion;
};

/**
 * Holds data of event that arrives when custom context event is emitted.
 */
struct ContextCustomEvent : public core::Event {

    /**
     * Event constructor
     */
    ContextCustomEvent() : core::Event("contextCustom") {}

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
     * Event's data
     */
    ContextCustomEventData data;
};

/**
 * 'Events' provides the helpers methods for module's events management.
 */
class Events {
public:

    /**
     * Checks whether event held in the 'EventHolder' is an 'ContextCustomEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'ContextCustomEvent', else otherwise
     */
    static bool isContextCustomEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'ContextCustomEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'ContextCustomEvent' object
     */
    static ContextCustomEvent extractContextCustomEvent(const core::EventHolder& eventHolder);

};

}  // event
}  // endpoint
}  // privmx

#endif // _PRIVMXLIB_ENDPOINT_EVENT_EVENTS_HPP_