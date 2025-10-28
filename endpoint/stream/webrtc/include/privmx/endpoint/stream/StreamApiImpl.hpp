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
#include <privmx/endpoint/event/EventApi.hpp>
#include "privmx/endpoint/stream/Types.hpp"
#include "privmx/endpoint/stream/PmxPeerConnectionObserver.hpp"
#include "privmx/endpoint/stream/StreamApiLow.hpp"
#include "privmx/endpoint/stream/WebRTCImpl.hpp"
#include "privmx/endpoint/stream/PeerConnectionManager.hpp"
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

    // Subscribing
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
    void unpublishStream(const StreamHandle& streamHandle);
    void subscribeToRemoteStream(const std::string& streamRoomId, const RemoteStreamId& streamId, const std::optional<std::vector<RemoteTrackId>>& tracksIds, const StreamSettings& options);
    void subscribeToRemoteStreams(const std::string& streamRoomId, std::vector<RemoteStreamId> streamsIds, const StreamSettings& options);
    void modifyRemoteStreamSubscription(const std::string& streamRoomId, const RemoteStreamId& streamId, const StreamSettings& options, const std::optional<std::vector<RemoteTrackId>>& tracksIdsToAdd, const std::optional<std::vector<RemoteTrackId>>& tracksIdsToRemove);
    void unsubscribeFromRemoteStream(const std::string& streamRoomId, const RemoteStreamId& streamId);
    void unsubscribeFromRemoteStreams(const std::string& streamRoomId, const std::vector<RemoteStreamId>& streamsIds);
    void dropBrokenFrames(const std::string& streamRoomId, bool enable);


private:
    enum StreamStatus {
        Offline = 0,
        Online = 1
    };
    struct StreamData {
        StreamData(
            privmx::utils::ThreadSaveMap<int64_t, libwebrtc::scoped_refptr<libwebrtc::RTCVideoCapturer>> _streamCapturers,
            StreamStatus _status, std::string _streamRoomId
        ) :streamCapturers(_streamCapturers), status(_status), streamRoomId(_streamRoomId) {}
        privmx::utils::ThreadSaveMap<int64_t, libwebrtc::scoped_refptr<libwebrtc::RTCVideoCapturer>> streamCapturers;
        StreamStatus status;
        std::mutex streamMutex;
        std::string streamRoomId;
    };


    int64_t generateNumericId();

    void trackAddAudio(int64_t streamId, int64_t id = 0, const std::string& params_JSON = "{}");
    void trackAddVideo(int64_t streamId, int64_t id = 0, const std::string& params_JSON = "{}");
    void trackAddDesktop(int64_t streamId, int64_t id = 0, const std::string& params_JSON = "{}");
    void trackRemoveAudio(int64_t streamId, int64_t id = 0);
    void trackRemoveVideo(int64_t streamId, int64_t id = 0);
    void trackRemoveDesktop(int64_t streamId, int64_t id = 0);

    // v3 webrtc
    libwebrtc::scoped_refptr<libwebrtc::RTCPeerConnectionFactory> _peerConnectionFactory;
    privmx::utils::ThreadSaveMap<StreamHandle, std::shared_ptr<StreamData>> _streamDataMap;
    libwebrtc::scoped_refptr<libwebrtc::RTCMediaConstraints> _constraints;
    libwebrtc::RTCConfiguration _configuration;
    privmx::webrtc::FrameCryptorOptions _frameCryptorOptions;
    int _notificationListenerId, _connectedListenerId, _disconnectedListenerId;
    std::shared_ptr<StreamApiLow> _api;
    std::shared_ptr<WebRTCImpl> _webRTC;
};

}  // namespace stream
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPIIMPL_HPP_
