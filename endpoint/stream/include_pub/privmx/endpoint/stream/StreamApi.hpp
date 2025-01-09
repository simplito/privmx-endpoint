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
#include <privmx/endpoint/core/Types.hpp>
#include "privmx/endpoint/stream/Types.hpp"

namespace privmx {
namespace endpoint {
namespace stream {

class StreamApiImpl;

class StreamApi {
public:

    static StreamApi create(core::Connection& connetion);
    StreamApi() = default;

    // std::string roomCreate(
    //     const std::string& contextId, 
    //     const std::vector<core::UserWithPubKey>& users, 
    //     const std::vector<core::UserWithPubKey>&managers,
    //     const core::Buffer& publicMeta, 
    //     const core::Buffer& privateMeta,
    //     const std::optional<core::ContainerPolicy>& policies
    // );

    // void roomUpdate(
    //     const std::string& streamRoomId, 
    //     const std::vector<core::UserWithPubKey>& users, 
    //     const std::vector<core::UserWithPubKey>&managers,
    //     const core::Buffer& publicMeta, 
    //     const core::Buffer& privateMeta, 
    //     const int64_t version, 
    //     const bool force, 
    //     const bool forceGenerateNewKey, 
    //     const std::optional<core::ContainerPolicy>& policies
    // );

    // core::PagingList<StreamRoom> streamRoomList(const std::string& contextId, const core::PagingQuery& query);

    // StreamRoom streamRoomGet(const std::string& streamRoomId);

    // void streamRoomDelete(const std::string& streamRoomId);
    // Stream
    int64_t createStream(const std::string& streamRoomId);

    // Adding track
    std::vector<std::pair<int64_t, std::string>> listAudioRecordingDevices();
    std::vector<std::pair<int64_t, std::string>> listVideoRecordingDevices();
    std::vector<std::pair<int64_t, std::string>> listDesktopRecordingDevices();

    void trackAdd(int64_t streamId, int64_t id, DeviceType type, const std::string& params_JSON);
    
    // Publishing stream
    void publishStream(int64_t streamId);

    // Joining to Stream
    void joinStream(const std::string& streamRoomId, const std::vector<int64_t>& streamIds, const streamJoinSettings& settings);



    // void streamTrackRemove(const std::string& streamTrackId);
    // List<TrackInfo> streamTrackList(const std::string& streamRoomId, int64_t streamId);

    // // streamPublish
    // void streamPublish(int64_t streamId);

    // // // streamUnpublish
    // void streamUnpublish(int64_t streamId);

    // void streamJoin(const std::string& streamRoomId, const StreamAndTracksSelector& streamToJoin);
    // void streamLeave(int64_t streamId);

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
