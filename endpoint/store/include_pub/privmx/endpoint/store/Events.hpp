#ifndef _PRIVMXLIB_ENDPOINT_STORE_EVENTS_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_EVENTS_HPP_

#include "privmx/endpoint/core/Events.hpp"
#include "privmx/endpoint/store/Types.hpp"

namespace privmx {
namespace endpoint {
namespace store {

/**
 * Holds information of `StoreDeletedEvent`.
 */
struct StoreDeletedEventData {
    /**
     * Store ID
     */ 
    std::string storeId;
};

/**
 * Holds information of `StoreStatsChangedEvent`.
 */
struct StoreStatsChangedEventData {

    /**
     * Context ID
     */
    std::string contextId;
    
    /**
     * Store ID
     */
    std::string storeId;
    
    /**
     * last uploaded file date timestamp
     */
    int64_t lastFileDate;
    
    /**
     * total number of files
     */
    int64_t filesCount;
};

/**
 * Holds information of `StoreFileDeletedEvent`.
 */
struct StoreFileDeletedEventData {
    
    /**
     * Context ID
     */
    std::string contextId;
    
    /**
     * Store ID
     */
    std::string storeId;
    
    /**
     * file ID
     */
    std::string fileId;
};

/**
 * Holds data of event that arrives when Store is created.
 */
struct StoreCreatedEvent : public core::Event {

    /**
     * Event constructor
     */
    StoreCreatedEvent() : core::Event("storeCreated") {}

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
     * Store detailed info
     */
    Store data;
};

/**
 * Holds data of event that arrives when Store is updated.
 */
struct StoreUpdatedEvent : public core::Event {

    /**
     * Event constructor
     */
    StoreUpdatedEvent() : core::Event("storeUpdated") {}

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
    /// @brief Store detailed info
    Store data;
};

/**
 * Holds data of event that arrives when Store is deleted.
 */
struct StoreDeletedEvent : public core::Event {

    /**
     * Event constructor
     */
    StoreDeletedEvent() : core::Event("storeDeleted") {}

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
    StoreDeletedEventData data;
};
/**
 * Holds data of event that arrives when Store statistical data changes.
 */
struct StoreStatsChangedEvent : public core::Event {

    /**
     * Event constructor
     */
    StoreStatsChangedEvent() : core::Event("storeStatsChanged") {}

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

    StoreStatsChangedEventData data;
};

/**
 * Holds data of event that arrives when Store file is created.
 */
struct StoreFileCreatedEvent : public core::Event {

    /**
     * Event constructor
     */
    StoreFileCreatedEvent() : core::Event("storeFileCreated") {}

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
     * detailed Store file info
     */
    store::File data;
};

/**
 * Holds data of event that arrives when Store file is updated.
 */
struct StoreFileUpdatedEvent : public core::Event {

    /**
     * Event constructor
     */
    StoreFileUpdatedEvent() : core::Event("storeFileUpdated") {}

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
     * detailed Store file info
     */
    store::File data;
};

/**
 * Holds data of event that arrives when Store file is deleted.
 */
struct StoreFileDeletedEvent : public core::Event {

    /**
     * Event constructor
     */
    StoreFileDeletedEvent() : core::Event("storeFileDeleted") {}

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
    StoreFileDeletedEventData data;
};

/**
 * 'Events' provides the helpers methods for module's events management.
 */
class Events {
public:

    /**
     * Checks whether event held in the 'EventHolder' is an 'StoreCreatedEvent' 
     * 
     * @return true for 'StoreCreatedEvent', else otherwise
     */
    static bool isStoreCreatedEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'StoreCreatedEvent' 
     * 
     * @return 'StoreCreatedEvent' object
     */
    static StoreCreatedEvent extractStoreCreatedEvent(const core::EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is an 'StoreUpdatedEvent' 
     * 
     * @return true for 'StoreUpdatedEvent', else otherwise
     */
    static bool isStoreUpdatedEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'StoreUpdatedEvent' 
     * 
     * @return 'StoreUpdatedEvent' object
     */
    static StoreUpdatedEvent extractStoreUpdatedEvent(const core::EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is an 'StoreDeletedEvent' 
     * 
     * @return true for 'StoreDeletedEvent', else otherwise
     */
    static bool isStoreDeletedEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'StoreDeletedEvent' 
     * 
     * @return 'StoreDeletedEvent' object
     */
    static StoreDeletedEvent extractStoreDeletedEvent(const core::EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is an 'StoreStatsChangedEvent' 
     * 
     * @return true for 'StoreStatsChangedEvent', else otherwise
     */
    static bool isStoreStatsChangedEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'StoreStatsChangedEvent' 
     * 
     * @return 'StoreStatsChangedEvent' object
     */
    static StoreStatsChangedEvent extractStoreStatsChangedEvent(const core::EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is an 'StoreFileCreatedEvent' 
     * 
     * @return true for 'StoreFileCreatedEvent', else otherwise
     */
    static bool isStoreFileCreatedEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'StoreFileCreatedEvent' 
     * 
     * @return 'StoreFileCreatedEvent' object
     */
    static StoreFileCreatedEvent extractStoreFileCreatedEvent(const core::EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is an 'StoreFileUpdatedEvent' 
     * 
     * @return true for 'StoreFileUpdatedEvent', else otherwise
     */
    static bool isStoreFileUpdatedEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'StoreFileUpdatedEvent' 
     * 
     * @return 'StoreFileUpdatedEvent' object
     */
    static StoreFileUpdatedEvent extractStoreFileUpdatedEvent(const core::EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is an 'StoreFileDeletedEvent' 
     * 
     * @return true for 'StoreFileDeletedEvent', else otherwise
     */
    static bool isStoreFileDeletedEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'StoreFileDeletedEvent' 
     * 
     * @return 'StoreFileDeletedEvent' object
     */
    static StoreFileDeletedEvent extractStoreFileDeletedEvent(const core::EventHolder& eventHolder);
};


}
}
}

#endif