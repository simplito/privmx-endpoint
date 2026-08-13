/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPI_TYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPI_TYPES_HPP_

#include <privmx/endpoint/core/Buffer.hpp>
#include <privmx/endpoint/core/Types.hpp>

namespace privmx {
namespace endpoint {
namespace stream {
/**
 * Local handle to a Stream, allowing to manage the Stream and its feeds.
 */
using Handle = int64_t; // can be everything that is DTO

/**
 * Local handle to a publisher Stream, returned by createStream.
 * Allows to manage the Stream and the feeds it publishes.
 */
using StreamHandle = Handle;

/**
 * Local handle to a subscriber Stream, returned by createSubscriberStream.
 * Allows to manage the Stream and the feeds it is subscribed to.
 */
using SubscriberStreamHandle = Handle;

/**
 * Holds credentials of a TURN server.
 * Can be used to build an ICEServer for the WebRTC layer.
 * A TURN server relays the Streams when the network configuration blocks direct traffic, e.g. because of
 * a firewall or a double NAT.
 */
struct TurnCredentials {
    /**
     * URL of the TURN server
     */
    std::string url;

    /**
     * user name to authenticate with
     */
    std::string username;

    /**
     * password to authenticate with
     */
    std::string password;

    /**
     * timestamp after which the credentials are no longer valid
     */
    int64_t expirationTime;
};

/**
 * Holds all available information about a Stream Room.
 */
struct StreamRoom {
    /**
     * ID of the Context the Stream Room was created in
     */
    std::string contextId;

    /**
     * ID of the Stream Room
     */
    std::string streamRoomId;

    /**
     * Stream Room creation timestamp
     */
    int64_t createDate;

    /**
     * ID of the user who created the Stream Room
     */
    std::string creator;

    /**
     * Stream Room last modification timestamp
     */
    int64_t lastModificationDate;

    /**
     * ID of the user who last modified the Stream Room
     */
    std::string lastModifier;

    /**
     * list of users (their IDs) with access to the Stream Room
     */
    std::vector<std::string> users;

    /**
     * list of users (their IDs) with management rights
     */
    std::vector<std::string> managers;

    /**
     * version number (changes on updates)
     */
    int64_t version;

    /**
     * Stream Room's public metadata
     */
    core::Buffer publicMeta;

    /**
     * Stream Room's private metadata
     */
    core::Buffer privateMeta;

    /**
     * Stream Room's policies
     */
    core::ContainerPolicyWithoutItem policy;

    /**
     * status code of retrieval and decryption of the Stream Room
     */
    int64_t statusCode;

    /**
     * Version of the Stream Room data structure and how it is encoded/encrypted
     */
    int64_t schemaVersion;

    /**
     * current state of the Stream Room: "created" | "open" | "closed".
     * - "created" means that the Stream Room has been created for a future meeting and has not been used yet
     * - "open" means that the meeting in the Stream Room has started, that is the first user has joined it
     * - "closed" means that the meeting has ended - the Stream Room closes itself once all its users have left
     *   and the emptyRoomTtl grace period has passed. If a user joins before that period elapses, it starts over.
     */
    std::string state;

    /**
     * grace period (ms) the Stream Room stays open after the last participant leaves
     */
    int64_t emptyRoomTtl;
};

/**
 * Holds a WebRTC session description together with its type.
 */
struct SdpWithTypeModel {
    /**
     * session description in the SDP format
     */
    std::string sdp;

    /**
     * type of the session description ("offer" or "answer")
     */
    std::string type;
};

/**
 * Describes a single subscription to a remote Stream or one of its tracks.
 */
struct StreamSubscription {
    /**
     * ID of the remote Stream to subscribe to
     */
    int64_t streamId;

    /**
     * ID of the track to subscribe to, or no value to subscribe to the whole Stream
     */
    std::optional<std::string> streamTrackId;
};

/**
 * Types of Stream Room events that can be subscribed for.
 */
enum EventType : int64_t {
    /**
     * a Stream Room has been created
     */
    STREAMROOM_CREATE = 0,

    /**
     * a Stream Room has been updated
     */
    STREAMROOM_UPDATE = 1,

    /**
     * a Stream Room has been deleted
     */
    STREAMROOM_DELETE = 2,

    /**
     * a user has joined a Stream Room
     */
    STREAMROOM_JOIN = 3,

    /**
     * a user has left a Stream Room
     */
    STREAMROOM_LEAVE = 4,

    /**
     * a Stream has been published
     */
    STREAM_PUBLISH = 5,

    /**
     * a Stream has stopped being published
     */
    STREAM_UNPUBLISH = 6,

    /**
     * a user has subscribed to a Stream
     */
    STREAM_SUBSCRIBE = 7,

    /**
     * a user has unsubscribed from a Stream
     */
    STREAM_UNSUBSCRIBE = 8,

    /**
     * a published Stream has been updated (its tracks changed)
     */
    STREAM_UPDATE = 9,
};

/**
 * Scopes on which Stream Room events can be listened for.
 */
enum EventSelectorType : int64_t {
    /**
     * listen for events in the whole Context
     */
    CONTEXT_ID = 0,

    /**
     * listen for events in a single Stream Room
     */
    STREAMROOM_ID = 1,

    /**
     * listen for events concerning a single Stream
     */
    STREAM_ID = 2,
};

/**
 * Holds information about a single track.
 */
struct StreamTrackInfo {
    /**
     * type of the track (e.g. "audio", "video", "data")
     * - audio means audioTrack
     * - video means videoTrack
     * - data means data channel
     */
    std::string type;

    /**
     * index of the track's media line in the SDP
     */
    int64_t mindex;

    /**
     * media line ID of the track in the SDP
     */
    std::string mid;

    /**
     * determines whether the track is currently disabled by its publisher.
     * A disabled track may have been paused or completely removed by the publisher.
     */
    bool disabled;

    /**
     * codec used by the track, if known
     */
    std::optional<std::string> codec;

    /**
     * track description provided by its publisher
     */
    std::optional<std::string> description;

    /**
     * determines whether the track has been muted by a moderator
     */
    bool moderated;

    /**
     * determines whether the track is sent using simulcast
     */
    bool simulcast;
};

/**
 * Holds information about a Stream and its tracks.
 */
struct StreamInfo {
    /**
     * ID of the Stream
     */
    int64_t id;

    /**
     * ID of the user who published the Stream
     */
    std::string userId;

    /**
     * Stream's metadata in serialized JSON
     */
    std::optional<std::string> metadata;

    /**
     * determines whether the Stream is a dummy (placeholder) Stream
     */
    bool dummy;

    /**
     * details of the Stream's tracks
     */
    std::vector<StreamTrackInfo> tracks;
};

/**
 * Holds information about a modification of a single track.
 */
struct StreamTrackModificationPair {
    /**
     * state of the track before the modification, or no value if the track has just been added
     */
    std::optional<StreamTrackInfo> before;

    /**
     * state of the track after the modification, or no value if the track has been removed
     */
    std::optional<StreamTrackInfo> after;
};

/**
 * Holds information about a published Stream.
 */
struct PublishedStreamData {
    /**
     * StreamRoom ID
     */
    std::string streamRoomId;

    /**
     * Published stream info
     */
    StreamInfo stream;

    /**
     * ID of the user who published the Stream
     */
    std::string userId;
};

/**
 * Holds data of events related to joining and leaving a Stream Room.
 */
struct StreamRoomParticipantEventData {
    /**
     * ID of the StreamRoom this event concerns
     */
    std::string streamRoomId;

    /**
     * User ID of the member who joined or left the room
     */
    std::string userId;
};

/**
 * Holds data of events related to subscribing to and unsubscribing from Streams.
 */
struct StreamSubscriptionEventData {
    /**
     * ID of the StreamRoom this event concerns
     */
    std::string streamRoomId;

    /**
     * ID of the user who subscribed or unsubscribed
     */
    std::string userId;

    /**
     * List of stream subscriptions
     */
    std::vector<StreamSubscription> subscriptions;
};

/**
 * Holds data of an event informing about changes in a published Stream's tracks.
 */
struct StreamUpdatedEventData {
    /**
     * ID of the StreamRoom the event occurred in
     */
    std::string streamRoomId;

    /**
     * Publisher stream ID that changed
     */
    int64_t streamId;

    /**
     * ID of the user who publishes the Stream
     */
    std::string userId;

    /**
     * list of tracks added to the Stream
     */
    std::vector<StreamTrackInfo> tracksAdded;

    /**
     * list of tracks removed from the Stream
     */
    std::vector<StreamTrackInfo> tracksRemoved;

    /**
     * list of tracks modified in the Stream, with their state before and after the change
     */
    std::vector<StreamTrackModificationPair> tracksModified;
};

/**
 * Holds the result of publishing or updating a Stream.
 */
struct StreamPublishResult {
    /**
     * determines whether the Stream has been published
     */
    bool published;

    /**
     * information about the published Stream, or no value if it has not been published
     */
    std::optional<PublishedStreamData> data;
};

/**
 * Holds information about a participant of a Stream Room.
 * A participant may have no subscriptions and publish no Stream - such a participant is a Joiner, a user who has
 * joined the Stream Room and can listen for the events about the Streams in it.
 */
struct StreamSubscriber {
    /**
     * ID of the participant
     */
    std::string userId;

    /**
     * list of the participant's current subscriptions
     */
    std::vector<StreamSubscription> subscriptions;

    /**
     * Stream published by the participant, or no value if they publish nothing
     */
    std::optional<StreamInfo> publishedStream;
};

/**
 * Holds a message sent over a Stream's data channel.
 */
struct DataChannelMessage {
    /**
     * message's plain (unencrypted) content
     */
    core::Buffer data;

    /**
     * message's sequence number, used to detect replayed and out-of-order messages
     */
    int64_t seq;
};

/**
 * Holds a decrypted message received over a Stream's data channel.
 */
struct DecryptedDataChannelMessage : public DataChannelMessage {
    /**
     * status code of decryption of the message. A value other than 0 means that the message could not be decrypted
     * or that its data integrity has been violated
     */
    int64_t statusCode;
};

} // namespace stream
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPI_TYPES_HPP_
