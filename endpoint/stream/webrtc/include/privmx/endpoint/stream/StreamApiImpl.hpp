/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPIIMPL_HPP_
#define _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPIIMPL_HPP_

#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <unordered_map>

#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/KeyProvider.hpp>
#include <privmx/endpoint/core/Types.hpp>
#include <privmx/endpoint/core/EventMiddleware.hpp>
#include <privmx/endpoint/core/EventChannelManager.hpp>
#include <privmx/endpoint/core/SubscriptionHelper.hpp>
#include <privmx/endpoint/event/EventApi.hpp>
#include "privmx/endpoint/stream/Types.hpp"
#include "privmx/endpoint/stream/PmxPeerConnectionObserver.hpp"
#include "privmx/endpoint/stream/StreamApiLow.hpp"
#include "privmx/endpoint/stream/WebRTC.hpp"
#include <libwebrtc.h>
#include <rtc_audio_device.h>
#include <rtc_peerconnection.h>
#include <base/portable.h>
#include <rtc_mediaconstraints.h>
#include <rtc_peerconnection.h>
#include <pmx_frame_cryptor.h>

namespace privmx {
namespace endpoint {
namespace stream {

class StreamApiImpl {
public:
    StreamApiImpl(core::Connection& connection, event::EventApi eventApi);

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

    void keyManagement(bool disable);
    void dropBrokenFrames(bool enable);

private:
    
    int64_t generateNumericId();

    void trackAddAudio(int64_t streamId, int64_t id = 0, const std::string& params_JSON = "{}");
    void trackAddVideo(int64_t streamId, int64_t id = 0, const std::string& params_JSON = "{}");
    void trackAddDesktop(int64_t streamId, int64_t id = 0, const std::string& params_JSON = "{}");
    void trackRemoveAudio(int64_t streamId, int64_t id = 0);
    void trackRemoveVideo(int64_t streamId, int64_t id = 0);
    void trackRemoveDesktop(int64_t streamId, int64_t id = 0);

    // v3 webrtc
    libwebrtc::scoped_refptr<libwebrtc::RTCPeerConnectionFactory> _peerConnectionFactory;
    privmx::utils::ThreadSaveMap<uint64_t, std::shared_ptr<WebRTC>> _streamDataMap;
    privmx::utils::ThreadSaveMap<uint64_t, privmx::utils::ThreadSaveMap<int64_t, libwebrtc::scoped_refptr<libwebrtc::RTCVideoCapturer>>::Ptr> _streamCapturers;


    libwebrtc::scoped_refptr<libwebrtc::RTCMediaConstraints> _constraints;
    libwebrtc::RTCConfiguration _configuration;
    privmx::webrtc::FrameCryptorOptions _frameCryptorOptions;
    int _notificationListenerId, _connectedListenerId, _disconnectedListenerId;
    std::shared_ptr<StreamApiLow> _api;
};

}  // namespace stream
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPIIMPL_HPP_
