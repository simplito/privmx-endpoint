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
using Handle = int64_t; // can be everything that is DTO
using StreamHandle = Handle;
using SubscriberStreamHandle = Handle;
using RemoteStreamId = int64_t;
using RemoteTrackId = std::string;

/**
 * Additional stream settings.
 * Reserved for future use.
*/
struct Settings {};

struct TurnCredentials {
    std::string url;
    std::string username;
    std::string password;
    int64_t expirationTime;
};

struct StreamRoom {
    std::string contextId;
    std::string streamRoomId;
    int64_t createDate;
    std::string creator;
    int64_t lastModificationDate;
    std::string lastModifier;
    std::vector<std::string> users;
    std::vector<std::string> managers;
    int64_t version;
    core::Buffer publicMeta;
    core::Buffer privateMeta;
    core::ContainerPolicyWithoutItem policy;
    int64_t statusCode;
    int64_t schemaVersion;
    bool closed;
};

struct Stream {
    int64_t streamId;
    std::string userId;
};

struct SdpWithTypeModel {
    std::string sdp;
    std::string type;
};

struct StreamSubscription {
    int64_t streamId;
    std::optional<std::string> streamTrackId;
};

enum EventType : int64_t {
    STREAMROOM_CREATE = 0,
    STREAMROOM_UPDATE = 1,
    STREAMROOM_DELETE = 2,
    STREAMROOM_JOIN = 4,
    STREAMROOM_LEAVE = 5,
    STREAM_PUBLISH = 6,
    STREAM_UNPUBLISH = 7,
    STREAM_SUBSCRIBE = 8,
    STREAM_UNSUBSCRIBE = 9,
    STREAM_UPDATE = 10,
};

enum EventSelectorType : int64_t {
    CONTEXT_ID = 0,
    STREAMROOM_ID = 1,
    STREAM_ID = 2,
};

struct StreamTrackInfo {
    std::string type;                       // "audio" | "video" | "data"
    int64_t mindex;                         // unikalny mindex strumienia
    std::string mid;                        // unikalny mid
    std::optional<bool> disabled;           // czy strumień jest nieaktywny
    std::optional<std::string> codec;       // np. "opus", "vp8"
    std::optional<std::string> description; // opis strumienia
    std::optional<bool> moderated;          // czy zmoderowany
    std::optional<bool> simulcast;          // czy używa simulcast
};

struct StreamInfo {
    int64_t id;                          // unikalny ID wydawcy
    std::string userId;                  // nazwa użytkownika
    std::optional<std::string> metadata; // metadane jako tekst JSON
    std::optional<bool> dummy;           // czy to publisher-dummy
    std::vector<StreamTrackInfo> tracks; // lista trackow
};

struct StreamTrackModificationPair {
    std::optional<StreamTrackInfo> before;
    std::optional<StreamTrackInfo> after;
};

struct PublishedStreamData {
    /**
     * StreamRoom ID
     */
    std::string streamRoomId;

    /**
     * Published stream info
     */
    StreamInfo stream;

    std::string userId;
};

struct StreamRoomParticipantEventData {
    /**
     * StreamRoom ID
     */
    std::string streamRoomId;

    /**
     * User ID of the member who joined or left
     */
    std::string userId;
};

struct StreamSubscriptionEventData {
    /**
     * StreamRoom ID
     */
    std::string streamRoomId;

    /**
     * User ID of the subscriber
     */
    std::string userId;

    /**
     * List of stream subscriptions
     */
    std::vector<StreamSubscription> subscriptions;
};

struct StreamUpdatedEventData {
    /**
     * StreamRoom ID
     */
    std::string streamRoomId;

    /**
     * Publisher stream ID that changed
     */
    int64_t streamId;

    /**
     * User ID of who changed it
     */
    std::string userId;

    std::vector<StreamTrackInfo> tracksAdded;

    std::vector<StreamTrackInfo> tracksRemoved;

    std::vector<StreamTrackModificationPair> tracksModified;
};

struct StreamPublishResult {
    bool published;
    std::optional<PublishedStreamData> data;
};

struct RecordingEncKey {
    core::Buffer id;
    core::Buffer key;
};

struct DataChannelMessage {
    core::Buffer data;
    int64_t seq;
};

struct DecryptedDataChannelMessage : public DataChannelMessage {
    int64_t statusCode;
};

} // namespace stream
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPI_TYPES_HPP_
