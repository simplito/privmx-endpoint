#ifndef _PRIVMXLIB_ENDPOINT_THREAD_EVENTS_HPP_
#define _PRIVMXLIB_ENDPOINT_THREAD_EVENTS_HPP_

#include "privmx/endpoint/core/Events.hpp"
#include "privmx/endpoint/core/Types.hpp"
#include "privmx/endpoint/thread/Types.hpp"

namespace privmx {
namespace endpoint {
namespace thread {

struct ThreadDeletedEventData {
    
    /**
     * Thread ID
     */
    std::string threadId;
};

/**
 * Holds information of `ThreadDeletedMessageEvent`.
 */
struct ThreadDeletedMessageEventData {

    /**
     * Thread ID
     */
    std::string threadId;

    /**
     * message ID
     */
    std::string messageId;
};

/**
 * Holds Thread statistical data.
 */
struct ThreadStatsEventData {

    /**
     * Thread ID
     */
    std::string threadId;

    /**
     * timestamp of the most recent Thread message
     */
    int64_t lastMsgDate;

    /**
     * updated number of messages in the Thread
     */
    int64_t messagesCount;
};

/**
 * Holds data of event that arrives when Thread is created.
 */
struct ThreadCreatedEvent : public core::Event {

    /**
     * Event constructor
     */
    ThreadCreatedEvent() : core::Event("threadCreated") {}

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
     * all available Thread information
     */
    Thread data;
};

/**
 * Holds data of event that arrives when Thread is updated.
 */
struct ThreadUpdatedEvent : public core::Event {
    
    /**
     * Event constructor
     */
    ThreadUpdatedEvent() : core::Event("threadUpdated") {}

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
     * all available Thread information
     */
    Thread data;
};

/**
 * Holds data of event that arrives when Thread is deleted.
 */
struct ThreadDeletedEvent : public core::Event {
    
    /**
     * Event constructor
     */
    ThreadDeletedEvent() : core::Event("threadDeleted") {}

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
    ThreadDeletedEventData data;
};

/**
 * Holds data of event that arrives when Thread message is created.
 */
struct ThreadNewMessageEvent : public core::Event {
    
    /**
     * Event constructor
     */
    ThreadNewMessageEvent() : core::Event("threadNewMessage") {}

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
     * detailed information about Message
     */
    thread::Message data;
};

/**
 * Holds data of event that arrives when Thread message is updated.
 */
struct ThreadMessageUpdatedEvent : public core::Event {
    
    /**
     * Event constructor
     */
    ThreadMessageUpdatedEvent() : core::Event("threadUpdatedMessage") {}

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
     * detailed information about Message
     */
    thread::Message data;
};

/**
 * Holds data of event that arrives when Thread message is deleted.
 */
struct ThreadMessageDeletedEvent : public core::Event {
    
    /**
     * Event constructor
     */
    ThreadMessageDeletedEvent() : core::Event("threadMessageDeleted") {}

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
    ThreadDeletedMessageEventData data;
};

/**
 * Holds data of event that arrives when Thread stats change.
 */
struct ThreadStatsChangedEvent : public core::Event {
    
    /**
     * Event constructor
     */
    ThreadStatsChangedEvent() : core::Event("threadStatsChanged") {}

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
    ThreadStatsEventData data;
};

/**
 * 'Events' provides the helpers methods for module's events management.
 */
class Events {
public:

    /**
     * Checks whether event held in the 'EventHolder' is an 'ThreadCreatedEvent' 
     * 
     * @return true for 'ThreadCreatedEvent', else otherwise
     */
    static bool isThreadCreatedEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'ThreadCreatedEvent' 
     * 
     * @return 'ThreadCreatedEvent' object
     */
    static ThreadCreatedEvent extractThreadCreatedEvent(const core::EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is an 'ThreadUpdatedEvent' 
     * 
     * @return true for 'ThreadUpdatedEvent', else otherwise
     */
    static bool isThreadUpdatedEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'ThreadUpdatedEvent' 
     * 
     * @return 'ThreadUpdatedEvent' object
     */
    static ThreadUpdatedEvent extractThreadUpdatedEvent(const core::EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is an 'ThreadDeletedEvent' 
     * 
     * @return true for 'ThreadDeletedEvent', else otherwise
     */
    static bool isThreadDeletedEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'ThreadDeletedEvent' 
     * 
     * @return 'ThreadDeletedEvent' object
     */
    static ThreadDeletedEvent extractThreadDeletedEvent(const core::EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is an 'ThreadStatsChangedEvent' 
     * 
     * @return true for 'ThreadStatsChangedEvent', else otherwise
     */
    static bool isThreadStatsEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'ThreadStatsChangedEvent' 
     * 
     * @return 'ThreadStatsChangedEvent' object
     */
    static ThreadStatsChangedEvent extractThreadStatsEvent(const core::EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is an 'ThreadNewMessageEvent' 
     * 
     * @return true for 'ThreadNewMessageEvent', else otherwise
     */
    static bool isThreadNewMessageEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'ThreadNewMessageEvent' 
     * 
     * @return 'ThreadNewMessageEvent' object
     */
    static ThreadNewMessageEvent extractThreadNewMessageEvent(const core::EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is an 'ThreadMessageUpdatedEvent' 
     * 
     * @return true for 'ThreadMessageUpdatedEvent', else otherwise
     */
    static bool isThreadMessageUpdatedEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'ThreadMessageUpdatedEvent' 
     * 
     * @return 'ThreadMessageUpdatedEvent' object
     */
    static ThreadMessageUpdatedEvent extractThreadMessageUpdatedEvent(const core::EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is an 'ThreadMessageDeletedEvent' 
     * 
     * @return true for 'ThreadMessageDeletedEvent', else otherwise
     */
    static bool isThreadDeletedMessageEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'ThreadMessageDeletedEvent' 
     * 
     * @return 'ThreadMessageDeletedEvent' object
     */
    static ThreadMessageDeletedEvent extractThreadMessageDeletedEvent(const core::EventHolder& eventHolder);
};

}  // namespace thread
}  // namespace endpoint
}  // namespace privmx

#endif