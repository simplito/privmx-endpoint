#ifndef _PRIVMXLIB_ENDPOINT_KVDB_EVENTS_HPP_
#define _PRIVMXLIB_ENDPOINT_KVDB_EVENTS_HPP_

#include "privmx/endpoint/core/Events.hpp"
#include "privmx/endpoint/core/Types.hpp"
#include "privmx/endpoint/kvdb/Types.hpp"

namespace privmx {
namespace endpoint {
namespace kvdb {

/**
 * Holds information of `KvdbDeletedEvent`.
 */
struct KvdbDeletedEventData {
    
    /**
     * Kvdb ID
     */
    std::string kvdbId;
};

/**
 * Holds Kvdb statistical data.
 */
struct  KvdbStatsEventData {

    /**
     * Kvdb ID
     */
    std::string kvdbId;

    /**
     * timestamp of the most recent Kvdb item
     */
    int64_t lastEntryDate;

    /**
     * updated number of entries in the Kvdb
     */
    int64_t entries;
};

/**
 * Holds information of `KvdbDeletedEntryEvent`.
 */
struct KvdbDeletedEntryEventData {

    /**
     * Kvdb ID
     */
    std::string kvdbId;

    /**
     * Key of deleted Entry
     */
    std::string kvdbEntryKey;
};

struct KvdbCreatedEvent : public core::Event {

    /**
     * Event constructor
     */
    KvdbCreatedEvent() : core::Event("kvdbCreated") {}

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
     * all available Kvdb information
     */
    Kvdb data;
};


/**
 * Holds data of event that arrives when Kvdb is updated.
 */
struct KvdbUpdatedEvent : public core::Event {
    
    /**
     * Event constructor
     */
    KvdbUpdatedEvent() : core::Event("kvdbUpdated") {}

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
     * all available Kvdb information
     */
    Kvdb data;
};

/**
 * Holds data of event that arrives when Kvdb is deleted.
 */
struct KvdbDeletedEvent : public core::Event {
    
    /**
     * Event constructor
     */
    KvdbDeletedEvent() : core::Event("kvdbDeleted") {}

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
    KvdbDeletedEventData data;
};

/**
 * Holds data of event that arrives when Kvdb stats change.
 */
struct KvdbStatsChangedEvent : public core::Event {
    
    /**
     * Event constructor
     */
    KvdbStatsChangedEvent() : core::Event("kvdbStatsChanged") {}

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
    KvdbStatsEventData data;
};


/**
 * Holds data of event that arrives when Kvdb message is created.
 */
struct KvdbNewEntryEvent : public core::Event {
    
    /**
     * Event constructor
     */
    KvdbNewEntryEvent() : core::Event("kvdbNewItem") {}

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
     * detailed information about Item
     */
    kvdb::KvdbEntry data;
};

/**
 * Holds data of event that arrives when Kvdb message is updated.
 */
struct KvdbEntryUpdatedEvent : public core::Event {
    
    /**
     * Event constructor
     */
    KvdbEntryUpdatedEvent() : core::Event("kvdbUpdatedItem") {}

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
     * detailed information about Item
     */
    kvdb::KvdbEntry data;
};

/**
 * Holds data of event that arrives when Kvdb message is deleted.
 */
struct KvdbEntryDeletedEvent : public core::Event {
    
    /**
     * Event constructor
     */
    KvdbEntryDeletedEvent() : core::Event("kvdbEntryDeleted") {}

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
    KvdbDeletedEntryEventData data;
};

/**
 * 'Events' provides the helpers methods for module's events management.
 */
class Events {
public:

    /**
     * Checks whether event held in the 'EventHolder' is an 'KvdbCreatedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'KvdbCreatedEvent', else otherwise
     */
    static bool isKvdbCreatedEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'KvdbCreatedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'KvdbCreatedEvent' object
     */
    static KvdbCreatedEvent extractKvdbCreatedEvent(const core::EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is an 'KvdbUpdatedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'KvdbUpdatedEvent', else otherwise
     */
    static bool isKvdbUpdatedEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'KvdbUpdatedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'KvdbUpdatedEvent' object
     */
    static KvdbUpdatedEvent extractKvdbUpdatedEvent(const core::EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is an 'KvdbDeletedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'KvdbDeletedEvent', else otherwise
     */
    static bool isKvdbDeletedEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'KvdbDeletedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'KvdbDeletedEvent' object
     */
    static KvdbDeletedEvent extractKvdbDeletedEvent(const core::EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is an 'KvdbStatsChangedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'KvdbStatsChangedEvent', else otherwise
     */
    static bool isKvdbStatsEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'KvdbStatsChangedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'KvdbStatsChangedEvent' object
     */
    static KvdbStatsChangedEvent extractKvdbStatsEvent(const core::EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is an 'KvdbNewEntryEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'KvdbNewEntryEvent', else otherwise
     */
    static bool isKvdbNewEntryEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'KvdbNewEntryEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'KvdbNewEntryEvent' object
     */
    static KvdbNewEntryEvent extractKvdbNewEntryEvent(const core::EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is an 'KvdbEntryUpdatedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'KvdbEntryUpdatedEvent', else otherwise
     */
    static bool isKvdbEntryUpdatedEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'KvdbEntryUpdatedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'KvdbEntryUpdatedEvent' object
     */
    static KvdbEntryUpdatedEvent extractKvdbEntryUpdatedEvent(const core::EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is an 'KvdbEntryDeletedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'KvdbEntryDeletedEvent', else otherwise
     */
    static bool isKvdbEntryDeletedEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'KvdbEntryDeletedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'KvdbEntryDeletedEvent' object
     */
    static KvdbEntryDeletedEvent extractKvdbEntryDeletedEvent(const core::EventHolder& eventHolder);
};

}  // namespace kvdb
}  // namespace endpoint
}  // namespace privmx

#endif