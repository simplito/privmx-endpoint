/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STREAM_EVENTS_HPP_
#define _PRIVMXLIB_ENDPOINT_STREAM_EVENTS_HPP_

#include <privmx/endpoint/core/Events.hpp>
#include <privmx/endpoint/core/Types.hpp>
#include "privmx/endpoint/stream/Types.hpp"

namespace privmx {
namespace endpoint {
namespace stream {


struct StreamRoomDeletedEventData {
    /**
     * StreamRoom ID
     */
    std::string streamRoomId;
};

struct StreamEventData {
    /**
     * StreamRoom ID
     */
    std::string streamRoomId;

    /**
     * Stream ID's
     */
    std::vector<int64_t> streamIds;

    /**
     * Modifier Id
     */
    std::string userId;
};

/**
 * Holds data of event that arrives when StreamRoom is created.
 */
struct StreamRoomCreatedEvent : public core::Event {

    /**
     * Event constructor
     */
    StreamRoomCreatedEvent() : core::Event("streamRoomCreated") {}

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
     * all available StreamRoom information
     */
    StreamRoom data;
};

/**
 * Holds data of event that arrives when StreamRoom is updated.
 */
struct StreamRoomUpdatedEvent : public core::Event {

    /**
     * Event constructor
     */
    StreamRoomUpdatedEvent() : core::Event("streamRoomUpdated") {}

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
     * all available StreamRoom information
     */
    StreamRoom data;
};

/**
 * Holds data of event that arrives when StreamRoom is deleted.
 */
struct StreamRoomDeletedEvent : public core::Event {

    /**
     * Event constructor
     */
    StreamRoomDeletedEvent() : core::Event("streamRoomDeleted") {}

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
    StreamRoomDeletedEventData data;
};

/**
 * Holds data of event that arrives when Stream is published.
 */
struct StreamPublishedEvent : public core::Event {

    /**
     * Event constructor
     */
    StreamPublishedEvent() : core::Event("streamPublished") {}

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
    StreamEventData data;
};

/**
 * Holds data of event that arrives when Stream is published.
 */
struct StreamJoinedEvent : public core::Event {

    /**
     * Event constructor
     */
    StreamJoinedEvent() : core::Event("streamJoined") {}

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
    StreamEventData data;
};

/**
 * Holds data of event that arrives when Stream is published.
 */
struct StreamUnpublishedEvent : public core::Event {

    /**
     * Event constructor
     */
    StreamUnpublishedEvent() : core::Event("streamUnpublished") {}

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
    StreamEventData data;
};

/**
 * Holds data of event that arrives when Stream is left.
 */
struct StreamLeftEvent : public core::Event {

    /**
     * Event constructor
     */
    StreamLeftEvent() : core::Event("streamLeft") {}

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
    StreamEventData data;
};


/**
 * Holds data of event that arrives on StreamPublish - contains information about available publishers/streams one can subscribe to.
 */
struct StreamAvailablePublishersEvent : public core::Event {

    /**
     * Event constructor
     */
    StreamAvailablePublishersEvent() : core::Event("publisherAvailablePublishers") {}

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
    CurrentPublishersData data;
};


/**
 * Holds data of event that arrives after StreamJoin - contains information about updates on publishers streams one can subscribe to.
 */
struct PublishersStreamsUpdatedEvent : public core::Event {

    /**
     * Event constructor
     */
    PublishersStreamsUpdatedEvent() : core::Event("streamsUpdated") {}

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
    StreamsUpdatedData data;
};

/**
 * 'Events' provides the helpers methods for module's events management.
 */
class Events {
public:

    /**
     * Checks whether event held in the 'EventHolder' is an 'StreamRoomCreatedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'StreamRoomCreatedEvent', else otherwise
     */
    static bool isStreamRoomCreatedEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'StreamRoomCreatedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'StreamRoomCreatedEvent' object
     */
    static StreamRoomCreatedEvent extractStreamRoomCreatedEvent(const core::EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is an 'StreamRoomUpdatedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'StreamRoomUpdatedEvent', else otherwise
     */
    static bool isStreamRoomUpdatedEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'StreamRoomUpdatedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'StreamRoomUpdatedEvent' object
     */
    static StreamRoomUpdatedEvent extractStreamRoomUpdatedEvent(const core::EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is an 'StreamRoomDeletedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'StreamRoomDeletedEvent', else otherwise
     */
    static bool isStreamRoomDeletedEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'StreamRoomDeletedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'StreamRoomDeletedEvent' object
     */
    static StreamRoomDeletedEvent extractStreamRoomDeletedEvent(const core::EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is an 'StreamPublishedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'StreamPublishedEvent', else otherwise
     */
    static bool isStreamPublishedEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'StreamPublishedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'StreamPublishedEvent' object
     */
    static StreamPublishedEvent extractStreamPublishedEvent(const core::EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is an 'StreamJoinedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'StreamJoinedEvent', else otherwise
     */
    static bool isStreamJoinedEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'StreamJoinedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'StreamJoinedEvent' object
     */
    static StreamJoinedEvent extractStreamJoinedEvent(const core::EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is an 'StreamUnpublishedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'StreamUnpublishedEvent', else otherwise
     */
    static bool isStreamUnpublishedEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'StreamUnpublishedEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'StreamUnpublishedEvent' object
     */
    static StreamUnpublishedEvent extractStreamUnpublishedEvent(const core::EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is an 'StreamLeftEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'StreamLeftEvent', else otherwise
     */
    static bool isStreamLeftEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'StreamLeftEvent' 
     * 
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'StreamLeftEvent' object
     */
    static StreamLeftEvent extractStreamLeftEvent(const core::EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is an 'StreamAvailablePublishersEvent'
     *
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'StreamAvailablePublishersEvent', else otherwise
     */
    static bool isStreamAvailablePublishersEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'PublishersStreamsUpdatedEvent'
     *
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'StreamAvailablePublishersEvent' object
     */
    static StreamAvailablePublishersEvent extractStreamAvailablePublishersEvent(const core::EventHolder& eventHolder);


    /**
     * Checks whether event held in the 'EventHolder' is an 'PublishersStreamsUpdatedEvent'
     *
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'StreamAvailablePublishersEvent', else otherwise
     */
    static bool isPublishersStreamsUpdatedEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'PublishersStreamsUpdatedEvent'
     *
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'StreamAvailablePublishersEvent' object
     */
    static PublishersStreamsUpdatedEvent extractPublishersStreamsUpdatedEvent(const core::EventHolder& eventHolder);
};

}  // namespace stream
}  // namespace endpoint
}  // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_EVENTS_HPP_