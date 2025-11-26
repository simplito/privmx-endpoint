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
    std::vector<StreamInfo> listStreams(const std::string& streamRoomId);
    void joinStreamRoom(const std::string& streamRoomId); // required before createStream and openStream
    void leaveStreamRoom(const std::string& streamRoomId);
    StreamHandle createStream(const std::string& streamRoomId);
    std::vector<MediaDevice> getMediaDevices();
    MediaTrack addTrack(const StreamHandle& streamHandle, const MediaDevice& mediaDevice);
    void removeTrack(const StreamHandle& streamHandle, const MediaDevice& mediaDevice);
    StreamPublishResult publishStream(const StreamHandle& streamHandle);
    StreamPublishResult updateStream(const StreamHandle& streamHandle);
    void unpublishStream(const StreamHandle& streamHandle);
    void subscribeToRemoteStreams(const std::string& streamRoomId, const std::vector<StreamSubscription>& subscriptions, const StreamSettings& options);
    void modifyRemoteStreamsSubscriptions(const std::string& streamRoomId, const std::vector<StreamSubscription>& subscriptionsToAdd, const std::vector<StreamSubscription>& subscriptionsToRemove, const StreamSettings& options);
    void unsubscribeFromRemoteStreams(const std::string& streamRoomId, const std::vector<StreamSubscription>& subscriptionsToRemove);
    void dropBrokenFrames(const std::string& streamRoomId, bool enable);


private:
    enum StreamStatus {
        Offline = 0,
        Online = 1
    };

    enum TrackStatus {
        ToAdd = 0,
        ToRemove = 1,
        Published = 2,
    };

    struct StreamAudioTrackInfo {
        StreamAudioTrackInfo( 
            const libwebrtc::scoped_refptr<libwebrtc::RTCAudioDevice>& _device,
            const std::string& _deviceName,
            const std::string& _deviceId,
            const libwebrtc::scoped_refptr<libwebrtc::RTCAudioSource>& _source,
            const libwebrtc::scoped_refptr<libwebrtc::RTCAudioTrack>& _track,
            const TrackStatus& _status
        ) : 
            device(_device), 
            deviceName(_deviceName),
            deviceId(_deviceId),
            source(_source),
            track(_track),
            status(_status)
        {}
        libwebrtc::scoped_refptr<libwebrtc::RTCAudioDevice> device;
        std::string deviceName;
        std::string deviceId;
        libwebrtc::scoped_refptr<libwebrtc::RTCAudioSource> source;
        libwebrtc::scoped_refptr<libwebrtc::RTCAudioTrack> track;
        TrackStatus status;
    };

    struct StreamVideoTrackInfo {
        StreamVideoTrackInfo( 
            const libwebrtc::scoped_refptr<libwebrtc::RTCVideoDevice>& _device,
            const std::string& _deviceName,
            const std::string& _deviceId,
            const libwebrtc::scoped_refptr<libwebrtc::RTCVideoCapturer>& _capturer,
            const libwebrtc::scoped_refptr<libwebrtc::RTCVideoSource>& _source,
            const libwebrtc::scoped_refptr<libwebrtc::RTCVideoTrack>& _track,
            const TrackStatus& _status
        ) : 
            device(_device), 
            deviceName(_deviceName),
            deviceId(_deviceId),
            capturer(_capturer),
            source(_source),
            track(_track),
            status(_status)
        {}
        libwebrtc::scoped_refptr<libwebrtc::RTCVideoDevice> device;
        std::string deviceName;
        std::string deviceId;
        libwebrtc::scoped_refptr<libwebrtc::RTCVideoCapturer> capturer;
        libwebrtc::scoped_refptr<libwebrtc::RTCVideoSource> source;
        libwebrtc::scoped_refptr<libwebrtc::RTCVideoTrack> track;
        TrackStatus status;
    };

    struct StreamData {
        StreamData(
            utils::ThreadSaveMap<std::string, std::shared_ptr<StreamAudioTrackInfo>> _audioTracks,
            utils::ThreadSaveMap<std::string, std::shared_ptr<StreamVideoTrackInfo>> _videoTracks,
            StreamStatus _status, std::string _streamRoomId
        ) : 
            audioTracks(_audioTracks), 
            videoTracks(_videoTracks), 
            status(_status), 
            streamRoomId(_streamRoomId) 
        {}
        utils::ThreadSaveMap<std::string, std::shared_ptr<StreamAudioTrackInfo>> audioTracks;
        utils::ThreadSaveMap<std::string, std::shared_ptr<StreamVideoTrackInfo>> videoTracks;
        StreamStatus status;
        std::string streamRoomId;
        std::mutex streamMutex;
    };
    int64_t generateNumericId();
    inline std::string getTrimmedString(std::string s) {
        s.erase(std::find(s.begin(), s.end(), '\0'), s.end());
        return s;
    }

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
