/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPI_HPP_
#define _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPI_HPP_

#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <functional>

#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/event/EventApi.hpp>
#include <privmx/endpoint/core/Types.hpp>
#include "privmx/endpoint/stream/webrtc/Types.hpp"

namespace privmx {
namespace endpoint {
namespace stream {

class StreamApiImpl;

class StreamApi {
public:

    static StreamApi create(core::Connection& connection, event::EventApi& eventApi);
    StreamApi() = default;

    std::string createStreamRoom(
        const std::string& contextId, 
        const std::vector<core::UserWithPubKey>& users, 
        const std::vector<core::UserWithPubKey>&managers,
        const core::Buffer& publicMeta, 
        const core::Buffer& privateMeta,
        const std::optional<core::ContainerPolicy>& policies
    );

    void updateStreamRoom(
        const std::string& streamRoomId, 
        const std::vector<core::UserWithPubKey>& users, 
        const std::vector<core::UserWithPubKey>&managers,
        const core::Buffer& publicMeta, 
        const core::Buffer& privateMeta, 
        const int64_t version, 
        const bool force, 
        const bool forceGenerateNewKey, 
        const std::optional<core::ContainerPolicy>& policies
    );

    core::PagingList<StreamRoom> listStreamRooms(const std::string& contextId, const core::PagingQuery& query);

    StreamRoom getStreamRoom(const std::string& streamRoomId);

    void deleteStreamRoom(const std::string& streamRoomId);
    // Subscriptions
    std::vector<std::string> subscribeFor(const std::vector<std::string>& subscriptionQueries);
    void unsubscribeFrom(const std::vector<std::string>& subscriptionIds);
    std::string buildSubscriptionQuery(EventType eventType, EventSelectorType selectorType, const std::string& selectorId);

    // Stream
    std::vector<Stream> listStreams(const std::string& streamRoomId);
    void joinRoom(const std::string& streamRoomId); // required before createStream and openStream
    void leaveRoom(const std::string& streamRoomId);
    StreamHandle createStream(const std::string& streamRoomId);
    std::vector<MediaDevice> getMediaDevices();
    void addTrack(const StreamHandle& streamHandle, const MediaDevice& track);
    void removeTrack(const StreamHandle& streamHandle, const MediaDevice& track);
    RemoteStreamId publishStream(const StreamHandle& streamHandle);
    void unpublishStream(const std::string& streamRoomId, const RemoteStreamId& streamId);
    void openStream(const std::string& streamRoomId, const RemoteStreamId& streamId, const std::optional<std::vector<RemoteTrackId>>& tracksIds, const StreamSettings& options);
    void openStreams(const std::string& streamRoomId, const std::vector<RemoteStreamId>& streamId, const StreamSettings& options);
    void modifyStream(const std::string& streamRoomId, const RemoteStreamId& streamId, const StreamSettings& options, const std::optional<std::vector<RemoteTrackId>>& tracksIdsToAdd, const std::optional<std::vector<RemoteTrackId>>& tracksIdsToRemove);
    void closeStream(const std::string& streamRoomId, const RemoteStreamId& streamId);
    void closeStreams(const std::string& streamRoomId, const std::vector<RemoteStreamId>& streamsIds);
    void dropBrokenFrames(const std::string& streamRoomId, bool enable);

    std::shared_ptr<StreamApiImpl> getImpl() const { return _impl; }

private:
    void validateEndpoint();
    StreamApi(const std::shared_ptr<StreamApiImpl>& impl);
    std::shared_ptr<StreamApiImpl> _impl;
};

}  // namespace stream
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPI_HPP_
