#ifndef _PRIVMXLIB_ENDPOINT_INBOX_EVENTS_HPP_
#define _PRIVMXLIB_ENDPOINT_INBOX_EVENTS_HPP_

#include "privmx/endpoint/core/Connection.hpp"
#include "privmx/endpoint/core/Events.hpp"
#include "privmx/endpoint/core/Types.hpp"
#include "privmx/endpoint/thread/Types.hpp"
#include "privmx/endpoint/store/Types.hpp"
#include "privmx/endpoint/inbox/Types.hpp"

namespace privmx {
namespace endpoint {
namespace inbox {

struct InboxCreatedEvent : public core::Event {

    /**
     * Event constructor
     */
    InboxCreatedEvent() : core::Event("inboxCreated") {}

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
     * detailed information about Inbox
     */
    Inbox data;
};

struct InboxUpdatedEvent : public core::Event {

    /**
     * Event constructor
     */
    InboxUpdatedEvent() : core::Event("inboxUpdated") {}

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
     * detailed information about Inbox
     */
    Inbox data;
};

struct InboxDeletedEventData {

    /**
     * Inbox ID
     */
    std::string inboxId;
};

struct InboxDeletedEvent : public core::Event {

    /**
     * Event constructor
     */
    InboxDeletedEvent() : core::Event("inboxDeleted") {}

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
     * event data
     */
    InboxDeletedEventData data;
};

/**
 * Holds data of event that arrives when Inbox entry is created.
 */
struct InboxEntryCreatedEvent : public core::Event {

    /**
     * Event constructor
     */
    InboxEntryCreatedEvent() : core::Event("inboxEntryCreated") {}

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
     * detailed information aboug InboxEntry
     */
    inbox::InboxEntry data;
};

/**
 * Holds information of `InboxEntryDeleted` event data.
 */
struct InboxEntryDeletedEventData {
    
    /**
     * Inbox ID
     */
    std::string inboxId;
    
    /**
     * Inbox Entry ID
     */
    std::string entryId;
};

/**
 * Holds data of event that arrives when Thread message is deleted.
 */
struct InboxEntryDeletedEvent : public core::Event {

    /**
     * Event constructor
     */
    InboxEntryDeletedEvent() : core::Event("inboxEntryDeleted") {}

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
     * event data
     */
    InboxEntryDeletedEventData data;
};

/**
 * Holds data of event that arrives when custom inbox event is emitted.
 */
struct InboxCustomEvent : public core::Event {
    
    /**
     * Event constructor
     */
    InboxCustomEvent() : core::Event("inboxCustom") {}

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
     * id of inbox from which it was sent
     */
    std::string inboxId;
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
     * Checks whether event held in the 'EventHolder' is an 'InboxCreatedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'InboxCreatedEvent', else otherwise
     */
    static bool isInboxCreatedEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'InboxCreatedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'InboxCreatedEvent' object
     */
    static InboxCreatedEvent extractInboxCreatedEvent(const core::EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is an 'InboxUpdatedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'InboxUpdatedEvent', else otherwise
     */
    static bool isInboxUpdatedEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'InboxUpdatedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'InboxUpdatedEvent' object
     */
    static InboxUpdatedEvent extractInboxUpdatedEvent(const core::EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is an 'InboxDeletedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'InboxDeletedEvent', else otherwise
     */
    static bool isInboxDeletedEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'InboxDeletedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'InboxDeletedEvent' object
     */
    static InboxDeletedEvent extractInboxDeletedEvent(const core::EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is an 'InboxEntryCreatedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'InboxEntryCreatedEvent', else otherwise
     */
    static bool isInboxEntryCreatedEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'InboxEntryCreatedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'InboxEntryCreatedEvent' object
     */
    static InboxEntryCreatedEvent extractInboxEntryCreatedEvent(const core::EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is an 'InboxEntryDeletedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'InboxEntryDeletedEvent', else otherwise
     */
    static bool isInboxEntryDeletedEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'InboxEntryDeletedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'InboxEntryDeletedEvent' object
     */
    static InboxEntryDeletedEvent extractInboxEntryDeletedEvent(const core::EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is an 'InboxCustomEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'InboxCustomEvent', else otherwise
     */
    static bool isInboxCustomEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'InboxCustomEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'InboxCustomEvent' object
     */
    static InboxCustomEvent extractInboxCustomEvent(const core::EventHolder& eventHolder);
};


}
}
}

#endif