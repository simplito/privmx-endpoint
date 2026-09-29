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

#include "privmx/endpoint/stream/Types.hpp"
#include <privmx/endpoint/core/Events.hpp>
#include <privmx/endpoint/core/Types.hpp>

namespace privmx {
namespace endpoint {
namespace stream {

/**
 * Holds data of an event informing about a deleted Stream Room.
 */
struct StreamRoomDeletedEventData {
    /**
     * ID of the deleted StreamRoom
     */
    std::string streamRoomId;
};

/**
 * Holds data of an event informing about a Stream which is no longer published.
 */
struct StreamUnpublishedEventData {
    /**
     * ID of the StreamRoom the Stream was published in
     */
    std::string streamRoomId;

    /**
     * ID of the publisher Stream which stopped being published
     */
    int64_t streamId;
};

/**
 * Holds data of an event informing about a newly published Stream.
 */
using StreamPublishedEventData = PublishedStreamData;

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
     * information about the StreamRoom which has just been created
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
     * information about the StreamRoom after the update
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
     * information about the deleted StreamRoom
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
     * information about the published Stream
     */
    StreamPublishedEventData data;
};

/**
 * Holds data of event that arrives when someone modifies the list of published tracks.
 */
struct StreamUpdatedEvent : public core::Event {

    /**
     * Event constructor
     */
    StreamUpdatedEvent() : core::Event("streamUpdated") {}

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
     * information about the changes in the Publisher Stream's tracks
     */
    StreamUpdatedEventData data;
};

/**
 * Holds data of event that arrives when a user joins a StreamRoom.
 */
struct StreamRoomJoinedEvent : public core::Event {

    /**
     * Event constructor
     */
    StreamRoomJoinedEvent() : core::Event("streamRoomJoined") {}

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
     * information about the user who joined the StreamRoom
     */
    StreamRoomParticipantEventData data;
};

/**
 * Holds data of event that arrives when Stream stops being published.
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
     * information about the Stream which stopped being published
     */
    StreamUnpublishedEventData data;
};

/**
 * Holds data of event that arrives when a user leaves a StreamRoom.
 */
struct StreamRoomLeftEvent : public core::Event {

    /**
     * Event constructor
     */
    StreamRoomLeftEvent() : core::Event("streamRoomLeft") {}

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
     * information about the user who left the StreamRoom
     */
    StreamRoomParticipantEventData data;
};

/**
 * Holds data of event that arrives when a participant subscribes to feeds.
 */
struct StreamSubscribedEvent : public core::Event {

    /**
     * Event constructor
     */
    StreamSubscribedEvent() : core::Event("streamSubscribed") {}

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
     * information about the created subscriptions
     */
    StreamSubscriptionEventData data;
};

/**
 * Holds data of event that arrives when a participant unsubscribes from feeds.
 */
struct StreamUnsubscribedEvent : public core::Event {

    /**
     * Event constructor
     */
    StreamUnsubscribedEvent() : core::Event("streamUnsubscribed") {}

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
     * information about the removed subscriptions
     */
    StreamSubscriptionEventData data;
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
     * Checks whether event held in the 'EventHolder' is an 'StreamUpdatedEvent'
     *
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'StreamUpdatedEvent', else otherwise
     */
    static bool isStreamUpdatedEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as an 'StreamUpdatedEvent'
     *
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'StreamUpdatedEvent' object
     */
    static StreamUpdatedEvent extractStreamUpdatedEvent(const core::EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is a 'StreamRoomJoinedEvent'
     *
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'StreamRoomJoinedEvent', else otherwise
     */
    static bool isStreamRoomJoinedEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as a 'StreamRoomJoinedEvent'
     *
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'StreamRoomJoinedEvent' object
     */
    static StreamRoomJoinedEvent extractStreamRoomJoinedEvent(const core::EventHolder& eventHolder);

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
     * Checks whether event held in the 'EventHolder' is a 'StreamRoomLeftEvent'
     *
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'StreamRoomLeftEvent', else otherwise
     */
    static bool isStreamRoomLeftEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as a 'StreamRoomLeftEvent'
     *
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'StreamRoomLeftEvent' object
     */
    static StreamRoomLeftEvent extractStreamRoomLeftEvent(const core::EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is a 'StreamSubscribedEvent'
     *
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'StreamSubscribedEvent', else otherwise
     */
    static bool isStreamSubscribedEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as a 'StreamSubscribedEvent'
     *
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'StreamSubscribedEvent' object
     */
    static StreamSubscribedEvent extractStreamSubscribedEvent(const core::EventHolder& eventHolder);

    /**
     * Checks whether event held in the 'EventHolder' is a 'StreamUnsubscribedEvent'
     *
     * @param eventHolder holder object that wraps the 'Event'
     * @return true for 'StreamUnsubscribedEvent', else otherwise
     */
    static bool isStreamUnsubscribedEvent(const core::EventHolder& eventHolder);

    /**
     * Gets Event held in the 'EventHolder' as a 'StreamUnsubscribedEvent'
     *
     * @param eventHolder holder object that wraps the 'Event'
     * @return 'StreamUnsubscribedEvent' object
     */
    static StreamUnsubscribedEvent extractStreamUnsubscribedEvent(const core::EventHolder& eventHolder);
};

} // namespace stream
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_EVENTS_HPP_