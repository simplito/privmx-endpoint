/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STREAM_PMX_PEER_CONNECTIN_OBSERVER_HPP_
#define _PRIVMXLIB_ENDPOINT_STREAM_PMX_PEER_CONNECTIN_OBSERVER_HPP_

#include <string>
#include <libwebrtc.h>
#include <rtc_audio_device.h>
#include <rtc_peerconnection.h>
#include "privmx/endpoint/stream/webrtc/Types.hpp"
#include <privmx/utils/ThreadSaveMap.hpp>
#include <pmx_frame_cryptor.h>

namespace privmx {
namespace endpoint {
namespace stream {

class FrameImpl : public Frame {
public:
    FrameImpl(libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame> frame);
    virtual int ConvertToRGBA(uint8_t* dst_argb, int dst_stride_argb, int dest_width, int dest_height) override;
private:
    libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame> _frame;
};


template <typename VideoFrameT>
class RTCVideoRendererImpl : public libwebrtc::RTCVideoRenderer<VideoFrameT> {
public:
    inline RTCVideoRendererImpl(std::function<void(int64_t, int64_t, std::shared_ptr<Frame>, const std::string&)> onFrameCallback, const std::string& id) : _onFrameCallback(onFrameCallback), _id(id) {}
    virtual void OnFrame(VideoFrameT frame) override {
        std::unique_lock<std::mutex> lock(m);
        _onFrameCallback(frame->width(), frame->height(), std::make_shared<FrameImpl>(frame), _id);
    }
    void updateOnFrameCallback(std::function<void(int64_t, int64_t, std::shared_ptr<Frame>, const std::string&)> onFrameCallback) {
        std::unique_lock<std::mutex> lock(m);
        _onFrameCallback = onFrameCallback;
    }
private:
    std::function<void(int64_t, int64_t, std::shared_ptr<Frame>, const std::string&)> _onFrameCallback;
    std::mutex m;
    std::string _id;
};

class PmxPeerConnectionObserver : public libwebrtc::RTCPeerConnectionObserver {
public:
    PmxPeerConnectionObserver(
        libwebrtc::scoped_refptr<libwebrtc::RTCPeerConnectionFactory> peerConnectionFactory,
        const std::string& streamRoomId, 
        std::shared_ptr<privmx::webrtc::KeyStore> keys, 
        const privmx::webrtc::FrameCryptorOptions& options
    );
    void OnSignalingState(libwebrtc::RTCSignalingState state) override;
    void OnPeerConnectionState(libwebrtc::RTCPeerConnectionState state) override;
    void OnIceGatheringState(libwebrtc::RTCIceGatheringState state) override;
    void OnIceConnectionState(libwebrtc::RTCIceConnectionState state) override;
    void OnIceCandidate(libwebrtc::scoped_refptr<libwebrtc::RTCIceCandidate> candidate) override;
    void OnAddStream(libwebrtc::scoped_refptr<libwebrtc::RTCMediaStream> stream) override;
    void OnRemoveStream(libwebrtc::scoped_refptr<libwebrtc::RTCMediaStream> stream) override;
    void OnDataChannel(libwebrtc::scoped_refptr<libwebrtc::RTCDataChannel> data_channel) override;
    void OnRenegotiationNeeded() override;
    void OnTrack(libwebrtc::scoped_refptr<libwebrtc::RTCRtpTransceiver> transceiver) override;
    void OnAddTrack(libwebrtc::vector<libwebrtc::scoped_refptr<libwebrtc::RTCMediaStream>> streams, libwebrtc::scoped_refptr<libwebrtc::RTCRtpReceiver> receiver) override;
    void OnRemoveTrack(libwebrtc::scoped_refptr<libwebrtc::RTCRtpReceiver> receiver) override;

    void UpdateCurrentKeys(std::shared_ptr<privmx::webrtc::KeyStore> newKeys);
    void SetFrameCryptorOptions(privmx::webrtc::FrameCryptorOptions options);

    inline void setOnSignalingState(std::function<void(libwebrtc::RTCSignalingState)> callback) {_onSignalingState = callback;}
    inline void setOnPeerConnectionState(std::function<void(libwebrtc::RTCPeerConnectionState)> callback) {_onPeerConnectionState = callback;}
    inline void setOnIceGatheringState(std::function<void(libwebrtc::RTCIceGatheringState)> callback) {_onIceGatheringState = callback;}
    inline void setOnIceConnectionState(std::function<void(libwebrtc::RTCIceConnectionState)> callback) {_onIceConnectionState = callback;}
    inline void setOnIceCandidate(std::function<void(libwebrtc::scoped_refptr<libwebrtc::RTCIceCandidate>)> callback) {_onIceCandidate = callback;}
    inline void setOnAddStream(std::function<void(libwebrtc::scoped_refptr<libwebrtc::RTCMediaStream>)> callback) {_onAddStream = callback;}
    inline void setOnRemoveStream(std::function<void(libwebrtc::scoped_refptr<libwebrtc::RTCMediaStream>)> callback) {_onRemoveStream = callback;}
    inline void setOnDataChannel(std::function<void(libwebrtc::scoped_refptr<libwebrtc::RTCDataChannel>)> callback) {_onDataChannel = callback;}
    inline void setOnRenegotiationNeeded(std::function<void()> callback) {_onRenegotiationNeeded = callback;}
    inline void setOnTrack(std::function<void(libwebrtc::scoped_refptr<libwebrtc::RTCRtpTransceiver>)> callback) {_onTrack = callback;}
    inline void setOnAddTrack(std::function<void(libwebrtc::vector<libwebrtc::scoped_refptr<libwebrtc::RTCMediaStream>> streams, libwebrtc::scoped_refptr<libwebrtc::RTCRtpReceiver>)> callback) {_onAddTrack = callback;}
    inline void setOnRemoveTrack(std::function<void(libwebrtc::scoped_refptr<libwebrtc::RTCRtpReceiver>)> callback) {_onRemoveTrack = callback;}
    inline void setOnFrame(std::function<void(int64_t, int64_t, std::shared_ptr<Frame>, const std::string&)> callback) {_onFrameCallback = callback;}
private:
    libwebrtc::scoped_refptr<libwebrtc::RTCPeerConnectionFactory> _peerConnectionFactory;
    std::string _streamRoomId; 
    std::shared_ptr<privmx::webrtc::KeyStore> _currentKeys;
    std::optional<std::function<void(int64_t, int64_t, std::shared_ptr<Frame>, const std::string&)>> _onFrameCallback;
    privmx::utils::ThreadSaveMap<std::string, std::shared_ptr<privmx::webrtc::FrameCryptor>> _frameCryptors;
    privmx::webrtc::FrameCryptorOptions _options;

    std::optional<std::function<void(libwebrtc::RTCSignalingState)>> _onSignalingState;
    std::optional<std::function<void(libwebrtc::RTCPeerConnectionState)>> _onPeerConnectionState;
    std::optional<std::function<void(libwebrtc::RTCIceGatheringState)>> _onIceGatheringState;
    std::optional<std::function<void(libwebrtc::RTCIceConnectionState)>> _onIceConnectionState;
    std::optional<std::function<void(libwebrtc::scoped_refptr<libwebrtc::RTCIceCandidate>)>> _onIceCandidate;
    std::optional<std::function<void(libwebrtc::scoped_refptr<libwebrtc::RTCMediaStream>)>> _onAddStream;
    std::optional<std::function<void(libwebrtc::scoped_refptr<libwebrtc::RTCMediaStream>)>> _onRemoveStream;
    std::optional<std::function<void(libwebrtc::scoped_refptr<libwebrtc::RTCDataChannel>)>> _onDataChannel;
    std::optional<std::function<void()>> _onRenegotiationNeeded;
    std::optional<std::function<void(libwebrtc::scoped_refptr<libwebrtc::RTCRtpTransceiver>)>> _onTrack;
    std::optional<std::function<void(libwebrtc::vector<libwebrtc::scoped_refptr<libwebrtc::RTCMediaStream>>, libwebrtc::scoped_refptr<libwebrtc::RTCRtpReceiver>)>> _onAddTrack;
    std::optional<std::function<void(libwebrtc::scoped_refptr<libwebrtc::RTCRtpReceiver>)>> _onRemoveTrack;
};

} // stream
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_PMX_PEER_CONNECTIN_OBSERVER_HPP_
