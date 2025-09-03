#ifndef _PRIVMXLIB_ENDPOINT_CORE_EVENTS_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_EVENTS_HPP_

#include <memory>
#include <string>
#include <vector>

#include "privmx/endpoint/core/Types.hpp"

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

    /**
     * List of subscriptions Id for witch it is
     */
    std::vector<std::string> subscriptions;

    /**
     * Timestamp of the event
     * 
     * Represents the point in time when event occurred.
     * - For events received from Bridge, this value comes from Bridge.
     * - For events generated in the library, this is a local timestamp.
    */
    int64_t timestamp;
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
 * Event that can be emitted to break the waitEvent loop.
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
 * Contains information about the changed item in the collection.
*/
struct CollectionItemChange {

    /**
     * ID of the item
    */
    std::string itemId;

    /**
     * Item change action, which can be "create", "update" or "delete"
    */
    std::string action;
};

/**
 * Contains information about the changed collection.
*/
struct CollectionChangedEventData {
    /**
     * Type of the module
    */
    std::string moduleType;

    /**
     * ID of the module
    */
    std::string moduleId;

    /**
     * Count of affected items
    */
    int64_t affectedItemsCount;

    /**
     * List of item changes
    */
    std::vector<CollectionItemChange> items;
};

/**
 * Holds data of event that arrives when the collection is changed.
*/
struct CollectionChangedEvent : public Event {
    CollectionChangedEvent() : Event("collectionChanged") {}

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

    /**
     * Information about the changed collection.
    */
    CollectionChangedEventData data;
};

/**
 * Contains information about the user of the Context
*/
struct ContextUserEventData {
    /**
     * ID of the Context
    */
    std::string contextId;

    /**
     * User
    */
    UserWithPubKey user;
};

/**
 * Contains the user with their status change action
*/
struct UserWithAction {
    /**
     * User
    */
    UserWithPubKey user;

    /**
     * User status change action, which can be "login" or "logout"
    */
    std::string action;
};

/**
 * Contains information about changed statuses of users in the Context.
*/
struct ContextUsersStatusChangeData {
    /**
     * ID of the Context
    */
    std::string contextId;

    /**
     * List of users with their changed statuses
    */
    std::vector<UserWithAction> users;
};

struct ContextUserAddedEvent : public Event {
    /**
     * Event constructor
     */
    ContextUserAddedEvent() : Event("contextUserAdded") {}

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

    /**
     * Information about the added user
    */
    ContextUserEventData data;
};

struct ContextUserRemovedEvent : public Event {
    /**
     * Event constructor
     */
    ContextUserRemovedEvent() : Event("contextUserRemoved") {}

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

    /**
     * Information about the removed user
    */
    ContextUserEventData data;
};

struct ContextUsersStatusChangeEvent : public Event {
    /**
     * Event constructor
     */
    ContextUsersStatusChangeEvent() : Event("contextUserStatusChanged") {}

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

    /**
     * User status changes
    */
    ContextUsersStatusChangeData data;
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

    /**
     * Checks whether event held in the 'EventHolder' is an 'CollectionChangedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'CollectionChangedEvent', else otherwise
    */
    static bool isCollectionChangedEvent(const EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'CollectionChangedEvent'
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'CollectionChangedEvent' object
    */
    static CollectionChangedEvent extractCollectionChangedEvent(const EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is an 'ContextUserAddedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'ContextUserAddedEvent', else otherwise
     */    
    static bool isContextUserAddedEvent(const EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'ContextUserAddedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'ContextUserAddedEvent' object
     */
    static ContextUserAddedEvent extractContextUserAddedEvent(const EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is an 'ContextUserRemovedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'ContextUserRemovedEvent', else otherwise
     */    
    static bool isContextUserRemovedEvent(const EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'ContextUserRemovedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'ContextUserRemovedEvent' object
     */
    static ContextUserRemovedEvent extractContextUserRemovedEvent(const EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is an 'ContextUsersStatusChangeEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'ContextUsersStatusChangeEvent', else otherwise
     */    
    static bool isContextUsersStatusChangeEvent(const EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'ContextUsersStatusChangeEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'ContextUsersStatusChangeEvent' object
     */
    static ContextUsersStatusChangeEvent extractContextUsersStatusChangeEvent(const EventHolder& eventHolder);
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  //_PRIVMXLIB_ENDPOINT_CORE_EVENTS_HPP_
