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
#include "privmx/endpoint/stream/Types.hpp"
#include <privmx/utils/ThreadSaveMap.hpp>
#include "privmx/endpoint/stream/StreamKeyManager.hpp"
#include <pmx_frame_cryptor.h>

namespace privmx {
namespace endpoint {
namespace stream {

class FrameImpl : public Frame {
public:
    FrameImpl(libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame> frame);
    virtual int ConvertToARGB(uint8_t* dst_argb, int dst_stride_argb, int dest_width, int dest_height) override;
private:
    libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame> _frame;
};


template <typename VideoFrameT>
class RTCVideoRendererImpl : public libwebrtc::RTCVideoRenderer<VideoFrameT> {
public:
    inline RTCVideoRendererImpl(std::function<void(int64_t, int64_t, std::shared_ptr<Frame>, const std::string&)> onFrameCallback, const std::string& id) : _onFrameCallback(onFrameCallback), _id(id) {}
    virtual void OnFrame(VideoFrameT frame) override {
        _onFrameCallback(frame->width(), frame->height(), std::make_shared<FrameImpl>(frame), _id);
    }
private:
    std::function<void(int64_t, int64_t, std::shared_ptr<Frame>, const std::string&)> _onFrameCallback;
    std::string _id;
};

class PmxPeerConnectionObserver : public libwebrtc::RTCPeerConnectionObserver {
public:
    PmxPeerConnectionObserver(
        uint64_t streamId, 
        std::shared_ptr<StreamKeyManager> streamKeyManager, 
        std::function<void(int64_t, int64_t, std::shared_ptr<Frame>, const std::string&)> onFrameCallback
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
private:
    uint64_t _streamId; 
    std::shared_ptr<StreamKeyManager> _streamKeyManager;
    privmx::utils::ThreadSaveMap<std::string, int64_t> _frameCryptorsId;

    std::function<void(int64_t, int64_t, std::shared_ptr<Frame>, const std::string&)> _onFrameCallback;
};

} // stream
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_PMX_PEER_CONNECTIN_OBSERVER_HPP_
