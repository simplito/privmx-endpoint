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
struct  ThreadStatsEventData {

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
 * Holds data of event that arrives when custom thread event is emitted.
 */
struct ThreadCustomEvent : public core::Event {
    
    /**
     * Event constructor
     */
    ThreadCustomEvent() : core::Event("threadCustom") {}

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
     * id of thread from which it was sent
     */
    std::string threadId;
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
     * Checks whether event held in the 'EventHolder' is an 'ThreadCreatedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'ThreadCreatedEvent', else otherwise
     */
    static bool isThreadCreatedEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'ThreadCreatedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'ThreadCreatedEvent' object
     */
    static ThreadCreatedEvent extractThreadCreatedEvent(const core::EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is an 'ThreadUpdatedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'ThreadUpdatedEvent', else otherwise
     */
    static bool isThreadUpdatedEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'ThreadUpdatedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'ThreadUpdatedEvent' object
     */
    static ThreadUpdatedEvent extractThreadUpdatedEvent(const core::EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is an 'ThreadDeletedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'ThreadDeletedEvent', else otherwise
     */
    static bool isThreadDeletedEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'ThreadDeletedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'ThreadDeletedEvent' object
     */
    static ThreadDeletedEvent extractThreadDeletedEvent(const core::EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is an 'ThreadStatsChangedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'ThreadStatsChangedEvent', else otherwise
     */
    static bool isThreadStatsEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'ThreadStatsChangedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'ThreadStatsChangedEvent' object
     */
    static ThreadStatsChangedEvent extractThreadStatsEvent(const core::EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is an 'ThreadNewMessageEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'ThreadNewMessageEvent', else otherwise
     */
    static bool isThreadNewMessageEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'ThreadNewMessageEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'ThreadNewMessageEvent' object
     */
    static ThreadNewMessageEvent extractThreadNewMessageEvent(const core::EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is an 'ThreadMessageUpdatedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'ThreadMessageUpdatedEvent', else otherwise
     */
    static bool isThreadMessageUpdatedEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'ThreadMessageUpdatedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'ThreadMessageUpdatedEvent' object
     */
    static ThreadMessageUpdatedEvent extractThreadMessageUpdatedEvent(const core::EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is an 'ThreadMessageDeletedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'ThreadMessageDeletedEvent', else otherwise
     */
    static bool isThreadDeletedMessageEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'ThreadMessageDeletedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'ThreadMessageDeletedEvent' object
     */
    static ThreadMessageDeletedEvent extractThreadMessageDeletedEvent(const core::EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is an 'ThreadCustomEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'ThreadCustomEvent', else otherwise
     */
    static bool isThreadCustomEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'ThreadCustomEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'ThreadCustomEvent' object
     */
    static ThreadCustomEvent extractThreadCustomEvent(const core::EventHolder& eventHolder);
};

}  // namespace thread
}  // namespace endpoint
}  // namespace privmx

#endif