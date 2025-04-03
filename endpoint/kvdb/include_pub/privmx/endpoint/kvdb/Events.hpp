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
    int64_t lastItemDate;

    /**
     * updated number of items in the Kvdb
     */
    int64_t items;
};

/**
 * Holds information of `KvdbDeletedItemEvent`.
 */
struct KvdbDeletedItemEventData {

    /**
     * Kvdb ID
     */
    std::string kvdbId;

    /**
     * Key of deleted Item
     */
    std::string kvdbItemKey;
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
struct KvdbNewItemEvent : public core::Event {
    
    /**
     * Event constructor
     */
    KvdbNewItemEvent() : core::Event("kvdbNewItem") {}

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
    kvdb::Item data;
};

/**
 * Holds data of event that arrives when Kvdb message is updated.
 */
struct KvdbItemUpdatedEvent : public core::Event {
    
    /**
     * Event constructor
     */
    KvdbItemUpdatedEvent() : core::Event("kvdbUpdatedItem") {}

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
    kvdb::Item data;
};

/**
 * Holds data of event that arrives when Kvdb message is deleted.
 */
struct KvdbItemDeletedEvent : public core::Event {
    
    /**
     * Event constructor
     */
    KvdbItemDeletedEvent() : core::Event("kvdbItemDeleted") {}

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
    KvdbDeletedItemEventData data;
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
     * Checks whether event held in the 'EventHolder' is an 'KvdbNewItemEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'KvdbNewItemEvent', else otherwise
     */
    static bool isKvdbNewItemEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'KvdbNewItemEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'KvdbNewItemEvent' object
     */
    static KvdbNewItemEvent extractKvdbNewItemEvent(const core::EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is an 'KvdbItemUpdatedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'KvdbItemUpdatedEvent', else otherwise
     */
    static bool isKvdbItemUpdatedEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'KvdbItemUpdatedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'KvdbItemUpdatedEvent' object
     */
    static KvdbItemUpdatedEvent extractKvdbItemUpdatedEvent(const core::EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is an 'KvdbItemDeletedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'KvdbItemDeletedEvent', else otherwise
     */
    static bool isKvdbItemDeletedEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'KvdbItemDeletedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'KvdbItemDeletedEvent' object
     */
    static KvdbItemDeletedEvent extractKvdbItemDeletedEvent(const core::EventHolder& eventHolder);
};

}  // namespace kvdb
}  // namespace endpoint
}  // namespace privmx

#endif