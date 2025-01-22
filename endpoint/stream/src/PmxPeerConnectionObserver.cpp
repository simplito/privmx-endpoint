/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/
#include "privmx/endpoint/stream/PmxPeerConnectionObserver.hpp"
#include <rtc_video_frame.h>
#include <iostream>
#include <privmx/utils/Debug.hpp>

using namespace privmx::endpoint::stream;


FrameImpl::FrameImpl(libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame> frame) : _frame(frame) {}

int FrameImpl::ConvertToARGB(uint8_t* dst_argb, int dst_stride_argb, int dest_width, int dest_height) {
    return _frame->ConvertToARGB(libwebrtc::RTCVideoFrame::Type::kRGBA, dst_argb, dst_stride_argb, dest_width, dest_height);
}

PmxPeerConnectionObserver::PmxPeerConnectionObserver(
    uint64_t streamId, 
    std::shared_ptr<StreamKeyManager> streamKeyManager, 
    std::function<void(int64_t, int64_t, std::shared_ptr<Frame>, const std::string&)> onFrameCallback
) : _streamId(streamId), _streamKeyManager(streamKeyManager), _onFrameCallback(onFrameCallback) {}

void PmxPeerConnectionObserver::OnSignalingState([[maybe_unused]] libwebrtc::RTCSignalingState state) {
    PRIVMX_DEBUG("STREAMS", "API", std::to_string(_streamId) ": ON SIGNALING STATE")
}
void PmxPeerConnectionObserver::OnPeerConnectionState([[maybe_unused]] libwebrtc::RTCPeerConnectionState state) {
    PRIVMX_DEBUG("STREAMS", "API", std::to_string(_streamId) ": ON PEER CONNECTION STATE")
}
void PmxPeerConnectionObserver::OnIceGatheringState([[maybe_unused]] libwebrtc::RTCIceGatheringState state) {

}
void PmxPeerConnectionObserver::OnIceConnectionState([[maybe_unused]] libwebrtc::RTCIceConnectionState state) {

}
void PmxPeerConnectionObserver::OnIceCandidate([[maybe_unused]] libwebrtc::scoped_refptr<libwebrtc::RTCIceCandidate> candidate) {
    
}
void PmxPeerConnectionObserver::OnAddStream(libwebrtc::scoped_refptr<libwebrtc::RTCMediaStream> stream) {
    PRIVMX_DEBUG("STREAMS", "API", std::to_string(_streamId) ": STREAM ADDED")
    PRIVMX_DEBUG("STREAMS", "API", "stream->video_tracks().size() -> " + std::to_string(stream->video_tracks().size()))
    PRIVMX_DEBUG("STREAMS", "API", "stream->audio_tracks().size() -> " + std::to_string(stream->audio_tracks().size()))
    for(size_t i = 0; i < stream->video_tracks().size(); i++) { 
        RTCVideoRendererImpl<libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame>>* r {
            new RTCVideoRendererImpl<libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame>>(_onFrameCallback, std::to_string(_streamId) + "-" + std::to_string(i))
        };
        stream->video_tracks()[i]->AddRenderer(r);
    }


}
void PmxPeerConnectionObserver::OnRemoveStream([[maybe_unused]] libwebrtc::scoped_refptr<libwebrtc::RTCMediaStream> stream) {

}
void PmxPeerConnectionObserver::OnDataChannel([[maybe_unused]] libwebrtc::scoped_refptr<libwebrtc::RTCDataChannel> data_channel) {

}
void PmxPeerConnectionObserver::OnRenegotiationNeeded() {

};
void PmxPeerConnectionObserver::OnTrack([[maybe_unused]] libwebrtc::scoped_refptr<libwebrtc::RTCRtpTransceiver> transceiver) {
    PRIVMX_DEBUG("STREAMS", "API", std::to_string(_streamId) ": ON TRACK")
}
void PmxPeerConnectionObserver::OnAddTrack([[maybe_unused]] libwebrtc::vector<libwebrtc::scoped_refptr<libwebrtc::RTCMediaStream>> streams, [[maybe_unused]] libwebrtc::scoped_refptr<libwebrtc::RTCRtpReceiver> receiver) {
    PRIVMX_DEBUG("STREAMS", "API", std::to_string(_streamId) ": TRACK ADDED")
    std::shared_ptr<privmx::webrtc::FrameCryptor> frameCryptor = privmx::webrtc::FrameCryptorFactory::frameCryptorFromRtpReceiver(receiver, _streamKeyManager->getCurrentWebRtcKeyStore());
    _frameCryptorsId.set(receiver->id(), _streamKeyManager->addFrameCryptor(frameCryptor));
}
void PmxPeerConnectionObserver::OnRemoveTrack([[maybe_unused]] libwebrtc::scoped_refptr<libwebrtc::RTCRtpReceiver> receiver) {
    _streamKeyManager->removeFrameCryptor(_frameCryptorsId.get(receiver->id()).value());
    _frameCryptorsId.erase(receiver->id());
}


