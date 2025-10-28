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

#include "privmx/endpoint/stream/WebRTCInterface.hpp"
#include "privmx/endpoint/stream/PeerConnectionManager.hpp"
#include <privmx/utils/ThreadSaveMap.hpp>
#include <libwebrtc.h>
#include <rtc_audio_device.h>
#include <rtc_peerconnection.h>
#include <base/portable.h>
#include <rtc_mediaconstraints.h>
#include <rtc_peerconnection.h>
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
        std::function<void(const int64_t, const dynamic::RTCIceCandidate&)> onTrickle,
        privmx::webrtc::FrameCryptorOptions _frameCryptorOptions
    );
    ~WebRTCImpl();

    std::string createOfferAndSetLocalDescription(const std::string& streamRoomId) override;
    std::string createAnswerAndSetDescriptions(const std::string& streamRoomId, const std::string& sdp, const std::string& type) override;
    void setAnswerAndSetRemoteDescription(const std::string& streamRoomId, const std::string& sdp, const std::string& type) override;
    virtual void updateSessionId(const std::string& streamRoomId, const int64_t sessionId, const std::string& connectionType)override;
    
    void close(const std::string& streamRoomId) override;
    void updateKeys(const std::string& streamRoomId, const std::vector<Key>& keys) override;
    void AddAudioTrack(const std::string& streamRoomId, libwebrtc::scoped_refptr<libwebrtc::RTCAudioTrack> audioTrack, std::string id = 0);
    void AddVideoTrack(const std::string& streamRoomId, libwebrtc::scoped_refptr<libwebrtc::RTCVideoTrack> videoTrack, std::string id = 0);
    void RemoveAudioTrack(const std::string& streamRoomId, std::string id = 0);
    void RemoveVideoTrack(const std::string& streamRoomId, std::string id = 0);

    void setFrameCryptorOptions(const std::string& streamRoomId, const privmx::webrtc::FrameCryptorOptions& frameCryptorOptions);
    void setOnFrame(const std::string& streamRoomId, std::function<void(int64_t, int64_t, std::shared_ptr<Frame>, const std::string&)> OnFrame);
    void setOnVideoTrack(const std::string& streamRoomId, std::function<void(const std::string&)> OnVideoTrack);
    void setOnRemoveVideoTrack(const std::string& streamRoomId, std::function<void(const std::string&)> OnRemoveVideoTrack);


private:

    int64_t addKeyUpdateCallback(std::function<void(std::shared_ptr<privmx::webrtc::KeyStore>)> keyUpdateCallback);
    void removeKeyUpdateCallback(int64_t keyUpdateCallbackId);
    static std::shared_ptr<privmx::webrtc::KeyStore> createWebRtcKeyStore(const std::vector<privmx::endpoint::stream::Key>& keys);
    std::shared_ptr<PeerConnection> createPeerConnection(const std::string& streamRoomId);

    libwebrtc::scoped_refptr<libwebrtc::RTCPeerConnectionFactory> _peerConnectionFactory;
    libwebrtc::scoped_refptr<libwebrtc::RTCMediaConstraints> _constraints;
    libwebrtc::RTCConfiguration _configuration;
    std::function<void(const int64_t, const dynamic::RTCIceCandidate&)> _onTrickle;
    privmx::webrtc::FrameCryptorOptions _frameCryptorOptions;
    std::shared_ptr<PeerConnectionManager> _peerConnectionManager;
    privmx::utils::ThreadSaveMap<std::string, std::shared_ptr<privmx::webrtc::KeyStore>> _roomKeys;
};

} // namespace stream
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_WEBRTC_HPP_
