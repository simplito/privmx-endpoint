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

#include "privmx/endpoint/stream/WebRTCInterface.hpp"
#include "privmx/endpoint/stream/PmxPeerConnectionObserver.hpp"
#include <privmx/utils/ThreadSaveMap.hpp>
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

class WebRTC : public WebRTCInterface
{
public:
    WebRTC(
        libwebrtc::scoped_refptr<libwebrtc::RTCPeerConnectionFactory> peerConnectionFactory,
        libwebrtc::scoped_refptr<libwebrtc::RTCMediaConstraints> constraints,
        libwebrtc::RTCConfiguration configuration,
        int64_t streamId,
        privmx::webrtc::FrameCryptorOptions frameCryptorOptions,
        std::optional<std::function<void(int64_t, int64_t, std::shared_ptr<Frame>, const std::string&)>> OnFrame
    );
    ~WebRTC();
    std::string createOfferAndSetLocalDescription() override;
    std::string createAnswerAndSetDescriptions(const std::string& sdp, const std::string& type) override;
    void setAnswerAndSetRemoteDescription(const std::string& sdp, const std::string& type) override;
    void close() override;
    void updateKeys(const std::vector<Key>& keys) override;
    void AddTrack(libwebrtc::scoped_refptr<libwebrtc::RTCAudioTrack> audioTrack);
    void AddTrack(libwebrtc::scoped_refptr<libwebrtc::RTCVideoTrack> videoTrack);
    void setCryptorOptions(const privmx::webrtc::FrameCryptorOptions& options);
private:
    int64_t addKeyUpdateCallback(std::function<void(std::shared_ptr<privmx::webrtc::KeyStore>)> keyUpdateCallback);
    void removeKeyUpdateCallback(int64_t keyUpdateCallbackId);
    static std::shared_ptr<privmx::webrtc::KeyStore> createWebRtcKeyStore(const std::vector<privmx::endpoint::stream::Key>& keys);
    libwebrtc::scoped_refptr<libwebrtc::RTCPeerConnectionFactory> _peerConnectionFactory;
    libwebrtc::scoped_refptr<libwebrtc::RTCMediaConstraints> _constraints;
    libwebrtc::scoped_refptr<libwebrtc::RTCPeerConnection> _peerConnection;
    privmx::webrtc::FrameCryptorOptions _frameCryptorOptions;
    std::shared_ptr<PmxPeerConnectionObserver> _peerConnectionObserver;
    int64_t _streamId;
    std::shared_ptr<privmx::webrtc::KeyStore> _currentWebRtcKeys;
    std::atomic_int64_t _nextKeyUpdateCallbackId = 0;
    std::vector<std::shared_ptr<privmx::webrtc::FrameCryptor>> _frameCryptors;
};

} // namespace stream
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_WEBRTC_HPP_
