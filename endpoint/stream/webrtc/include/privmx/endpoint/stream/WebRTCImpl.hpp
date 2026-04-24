/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STREAM_WEBRTC_HPP_
#define _PRIVMXLIB_ENDPOINT_STREAM_WEBRTC_HPP_

#include <string>
#include <vector>
#include <functional>
#include <atomic>

#include "privmx/endpoint/stream/StreamApiLow.hpp"
#include "privmx/endpoint/stream/WebRTCInterface.hpp"
#include "privmx/endpoint/stream/PeerConnectionManager.hpp"
#include "privmx/endpoint/stream/webrtc/OnTrackInterface.hpp"
#include "privmx/endpoint/stream/encryptors/dataChannel/DataChannelMessageEncryptorV1.hpp"
#include <privmx/utils/ThreadSaveMap.hpp>
#include <libwebrtc.h>
#include <rtc_audio_device.h>
#include <rtc_peerconnection.h>
#include <base/portable.h>
#include <rtc_mediaconstraints.h>
#include <rtc_media_stream.h>
#include <pmx_frame_cryptor.h>

namespace privmx {
namespace endpoint {
namespace stream {

class WebRTCImpl : public WebRTCInterface
{
public:
    WebRTCImpl(
        libwebrtc::scoped_refptr<libwebrtc::RTCPeerConnectionFactory> peerConnectionFactory,
        libwebrtc::scoped_refptr<libwebrtc::RTCMediaConstraints> constraints,
        libwebrtc::RTCConfiguration configuration,
        std::function<void(const int64_t, const std::string&)> onTrickle,
        privmx::webrtc::FrameCryptorOptions _frameCryptorOptions,
        std::shared_ptr<StreamApiLow> apiLow
    );
    ~WebRTCImpl();
    std::string createOfferAndSetLocalDescription(const std::string& streamRoomId) override;
    std::string createAnswerAndSetDescriptions(const std::string& streamRoomId, const std::string& sdp, const std::string& type) override;
    void setAnswerAndSetRemoteDescription(const std::string& streamRoomId, const std::string& sdp, const std::string& type) override;
    virtual void updateSessionId(const std::string& streamRoomId, const int64_t sessionId, const std::string& connectionType)override;
    
    void close(const std::string& streamRoomId) override;
    void updateKeys(const std::string& streamRoomId, const std::vector<Key>& keys) override;

    void setFrameCryptorOptions(const std::string& streamRoomId, const privmx::webrtc::FrameCryptorOptions& frameCryptorOptions);
    void setOnTrackInterface(const std::string& streamRoomId, const std::optional<std::string>& streamId, std::shared_ptr<OnTrackInterface> onTrackInterface);

    void createPeerConnectionWithLocalStream(
        const std::string& streamRoomId, 
        const std::vector<std::pair<std::string, libwebrtc::scoped_refptr<libwebrtc::RTCAudioTrack>>>& audioTracks,
        const std::vector<std::pair<std::string, libwebrtc::scoped_refptr<libwebrtc::RTCVideoTrack>>>& videoTracks,
        const std::optional<std::pair<std::string, std::function<void(std::string)>*>>& dataChannel
    );

    void updatePeerConnectionWithLocalStream(
        const std::string& streamRoomId, 
        const std::vector<std::pair<std::string, libwebrtc::scoped_refptr<libwebrtc::RTCAudioTrack>>>& audioTracksToAdd,
        const std::vector<std::pair<std::string, libwebrtc::scoped_refptr<libwebrtc::RTCVideoTrack>>>& videoTracksToAdd,
        const std::vector<std::pair<std::string, libwebrtc::scoped_refptr<libwebrtc::RTCAudioTrack>>>& audioTracksToRemove,
        const std::vector<std::pair<std::string, libwebrtc::scoped_refptr<libwebrtc::RTCVideoTrack>>>& videoTracksToRemove,
        const std::optional<std::pair<std::string, std::function<void(std::string)>*>>& dataChannel
    );
    void addRemoteStreamListener(const std::string& streamRoomId, int64_t streamId, std::shared_ptr<OnTrackInterface> onTrack);
    void closeSingleConnection(const std::string& streamRoomId, ConnectionType connectionType);
private:
    void AddAudioTrack(std::shared_ptr<privmx::endpoint::stream::JanusConnection> jc, libwebrtc::scoped_refptr<libwebrtc::RTCAudioTrack> audioTrack, std::string id = "0");
    void AddVideoTrack(std::shared_ptr<privmx::endpoint::stream::JanusConnection> jc, libwebrtc::scoped_refptr<libwebrtc::RTCVideoTrack> videoTrack, std::string id = "0");
    void AddDataChannel(std::shared_ptr<privmx::endpoint::stream::JanusConnection> jc, const std::pair<std::string, std::function<void(std::string)>*>& dataChannelInfo, const std::string& streamRoomId);
    void RemoveAudioTrack(std::shared_ptr<privmx::endpoint::stream::JanusConnection> jc, std::string id = "0");
    void RemoveVideoTrack(std::shared_ptr<privmx::endpoint::stream::JanusConnection> jc, std::string id = "0");
    void RemoveDataChannel(std::shared_ptr<privmx::endpoint::stream::JanusConnection> jc);


    static std::shared_ptr<privmx::webrtc::KeyStore> createWebRtcKeyStore(const std::vector<privmx::endpoint::stream::Key>& keys);
    std::shared_ptr<PeerConnection> createPeerConnection(const std::string& streamRoomId);

    libwebrtc::scoped_refptr<libwebrtc::RTCPeerConnectionFactory> _peerConnectionFactory;
    libwebrtc::scoped_refptr<libwebrtc::RTCMediaConstraints> _constraints;
    libwebrtc::RTCConfiguration _configuration;
    privmx::webrtc::FrameCryptorOptions _frameCryptorOptions;
    std::shared_ptr<StreamApiLow> _apiLow;
    std::shared_ptr<PeerConnectionManager> _peerConnectionManager;
    libwebrtc::scoped_refptr<libwebrtc::RTCDataChannel> _bootstrapDataChannel;
};

} // namespace stream
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_WEBRTC_HPP_
