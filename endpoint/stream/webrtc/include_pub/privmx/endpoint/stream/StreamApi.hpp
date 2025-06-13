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
    // Stream
    int64_t createStream(const std::string& streamRoomId);

    std::vector<std::pair<int64_t, std::string>> listAudioRecordingDevices();
    std::vector<std::pair<int64_t, std::string>> listVideoRecordingDevices();
    std::vector<std::pair<int64_t, std::string>> listDesktopRecordingDevices();

    void trackAdd(int64_t streamId, const TrackParam& track);
    void trackRemove(int64_t streamId, const Track& track);
    
    void publishStream(int64_t streamId);

    int64_t joinStream(const std::string& streamRoomId, const std::vector<int64_t>& streamsId, const StreamJoinSettings& settings);

    std::vector<Stream> listStreams(const std::string& streamRoomId);

    void unpublishStream(int64_t streamId);

    void leaveStream(int64_t streamId);
    void subscribeForStreamEvents();
    void unsubscribeFromStreamEvents();

    void keyManagement(bool disable);
    void dropBrokenFrames(bool enable);

    void reconfigureStream(int64_t localStreamId, const std::string& optionsJSON = "{}");

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
