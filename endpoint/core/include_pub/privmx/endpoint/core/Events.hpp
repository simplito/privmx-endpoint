#ifndef _PRIVMXLIB_ENDPOINT_CORE_EVENTS_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_EVENTS_HPP_

#include <memory>
#include <string>

namespace privmx {
namespace endpoint {
namespace core {

struct SerializedEvent;



/**
 * Holds the information about an event.
 */
struct Event {

    /**
     * 'Event' class constructor
     * 
     * @param type event type
     */
    Event(const std::string& type);

    /**
     * //doc-gen:ignore
     */
    virtual ~Event() = default;
    
    /**
     * Converts Event's data to JSON string
     * 
     * @return JSON string
     */
    virtual std::string toJSON() const = 0;

    /**
     * //doc-gen:ignore
     */
    virtual std::shared_ptr<SerializedEvent> serialize() const = 0;

    /**
     * Holds the type of the event
     */
    std::string type;

    /**
     * Holds the channel of the event
     */
    std::string channel;

    /**
     * ID of the connection (unique)
     */
    int64_t connectionId = -1;
};

/**
 * 'EventHolder' is an helper class containing functions to operate on 'Event' objects.
 */
class EventHolder {
public:

    /**
     * 'EventHolder' constructor
     * 
     * @param event pointer to the 'Event' object to use in the 'EventHolder'
     */
    EventHolder(const std::shared_ptr<Event>& event);
    
    /**
     * Extracts Event's type
     * 
     * @return type of the 'Event'
     */
    const std::string& type() const;

    /**
     * Extracts Event's channel
     * 
     * @return channel that the 'Event" arrived
     */
    const std::string& channel() const;

    /**
     * Serializes an Event to the JSON string
     * 
     * @return JSON string representation of the 'Event' object
     */
    std::string toJSON() const;

    /**
     * Gets 'Event' object
     * 
     * @return pointer to the underlying 'Event' object
     */
    const std::shared_ptr<Event>& get() const;

private:
    std::shared_ptr<Event> _event;
};

/**
 * Event that can be emmited to break the waitEvent loop.
 */
struct LibBreakEvent : public Event {

    /**
     * Event constructor
     */
    LibBreakEvent() : Event("libBreak") {}

    /**
     * Get Event as JSON string
     * 
     * @return JSON string
     */
    std::string toJSON() const override;

    /**
     * //doc-gen:ignore
     */
    std::shared_ptr<SerializedEvent> serialize() const override;
};

/**
 * Emitted when connection to the PrivMX Bridge Server has been lost
 */
struct LibPlatformDisconnectedEvent : public Event {

    /**
     * Event constructor
     */
    LibPlatformDisconnectedEvent() : Event("libPlatformDisconnected") {}

    /**
     * Get Event as JSON string
     * 
     * @return JSON string
     */
    std::string toJSON() const override;

    /**
     * //doc-gen:ignore
     */
    std::shared_ptr<SerializedEvent> serialize() const override;
};

/**
 * Emitted after connection to the Bridge Server has been established
 */
struct LibConnectedEvent : public Event {

    /**
     * Event constructor
     */
    LibConnectedEvent() : Event("libConnected") {}

    /**
     * Get Event as JSON string
     * 
     * @return JSON string
     */
    std::string toJSON() const override;

    /**
     * //doc-gen:ignore
     */
    std::shared_ptr<SerializedEvent> serialize() const override;
};


/**
 * Emitted after disconnection from the Endpoint by explicit disconnect call.
 */
struct LibDisconnectedEvent : public Event {

    /**
     * Event constructor
     */
    LibDisconnectedEvent() : Event("libDisconnected") {}

    /**
     * Get Event as JSON string
     * 
     * @return JSON string
     */
    std::string toJSON() const override;

    /**
     * //doc-gen:ignore
     */
    std::shared_ptr<SerializedEvent> serialize() const override;
};

/**
 * 'Events' provides the helpers methods for module's events management.
 */
class Events {
public:

    /**
     * Checks whether event held in the 'EventHolder' is an 'LibBreakEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'LibBreakEvent', else otherwise
     */
    static bool isLibBreakEvent(const EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'LibBreakEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'LibBreakEvent' object
     */
    static LibBreakEvent extractLibBreakEvent(const EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is an 'LibPlatformDisconnectedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'LibPlatformDisconnectedEvent', else otherwise
     */    
    static bool isLibPlatformDisconnectedEvent(const EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'LibPlatformDisconnectedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'LibPlatformDisconnectedEvent' object
     */
    static LibPlatformDisconnectedEvent extractLibPlatformDisconnectedEvent(const EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is an 'LibConnectedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'LibConnectedEvent', else otherwise
     */    
    static bool isLibConnectedEvent(const EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'LibConnectedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'LibConnectedEvent' object
     */
    static LibConnectedEvent extractLibConnectedEvent(const EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is an 'LibDisconnectedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'LibDisconnectedEvent', else otherwise
     */    
    static bool isLibDisconnectedEvent(const EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'LibDisconnectedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'LibDisconnectedEvent' object
     */
    static LibDisconnectedEvent extractLibDisconnectedEvent(const EventHolder& eventHolder);
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  //_PRIVMXLIB_ENDPOINT_CORE_EVENTS_HPP_
