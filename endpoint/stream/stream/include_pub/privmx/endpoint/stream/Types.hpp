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
#include <functional>

namespace privmx {
namespace endpoint {
namespace stream {

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
    core::ContainerPolicy policy;
    int64_t statusCode;
    int64_t schemaVersion;
};

struct Stream {
    int64_t streamId;
    std::string userId;
};

struct SdpWithTypeModel {
    std::string sdp;
    std::string type;
};

struct SdpWithTypeAndSessionModel {
    std::string roomId;
    int64_t sessionId;
    std::string sdp;
    std::string type;
};

enum EventType: int64_t {
    STREAMROOM_CREATE = 0,
    STREAMROOM_UPDATE = 1,
    STREAMROOM_DELETE = 2,
    STREAM_JOIN = 4,
    STREAM_LEAVE = 5,
    STREAM_PUBLISH = 6,
    STREAM_UNPUBLISH = 7,
};

enum EventSelectorType: int64_t {
    CONTEXT_ID = 0,
    STREAMROOM_ID = 1,
    STREAM_ID = 2,
};

struct VideoRoomStreamTrack {
    std::string type;
    std::string codec;
    std::string mid;
    int64_t mindex;
};

struct NewPublisherEvent {
    std::string id;
    std::string video_codec;
    std::vector<VideoRoomStreamTrack> streams;
};

struct CurrentPublishersData {
    std::string room;
    std::vector<NewPublisherEvent> publishers;
};

}  // namespace stream
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPI_TYPES_HPP_
