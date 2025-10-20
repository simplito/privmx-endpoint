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

int FrameImpl::ConvertToRGBA(uint8_t* dst_argb, int dst_stride_argb, int dest_width, int dest_height) {
    return _frame->ConvertToARGB(libwebrtc::RTCVideoFrame::Type::kRGBA, dst_argb, dst_stride_argb, dest_width, dest_height);
}

PmxPeerConnectionObserver::PmxPeerConnectionObserver(
    libwebrtc::scoped_refptr<libwebrtc::RTCPeerConnectionFactory> peerConnectionFactory,
    const std::string& streamRoomId, 
    std::shared_ptr<privmx::webrtc::KeyStore> keys, 
    const privmx::webrtc::FrameCryptorOptions& options
) : _peerConnectionFactory(peerConnectionFactory), _streamRoomId(streamRoomId), _currentKeys(keys), _options(options) {}

void PmxPeerConnectionObserver::OnSignalingState([[maybe_unused]] libwebrtc::RTCSignalingState state) {
    std::map<libwebrtc::RTCSignalingState, std::string> map = {
        {libwebrtc::RTCSignalingState::RTCSignalingStateStable, "RTCSignalingStateStable"},
        {libwebrtc::RTCSignalingState::RTCSignalingStateHaveLocalOffer, "RTCSignalingStateHaveLocalOffer"},
        {libwebrtc::RTCSignalingState::RTCSignalingStateHaveRemoteOffer, "RTCSignalingStateHaveRemoteOffer"},
        {libwebrtc::RTCSignalingState::RTCSignalingStateHaveLocalPrAnswer, "RTCSignalingStateHaveLocalPrAnswer"},
        {libwebrtc::RTCSignalingState::RTCSignalingStateHaveRemotePrAnswer, "RTCSignalingStateHaveRemotePrAnswer"},
        {libwebrtc::RTCSignalingState::RTCSignalingStateClosed, "RTCSignalingStateClosed"}
    };
    PRIVMX_DEBUG("STREAMS", "API", _streamRoomId + ": ON SIGNALING STATE " + map[state])
    if(_onSignalingState.has_value()) _onSignalingState.value()(state);
}
void PmxPeerConnectionObserver::OnPeerConnectionState([[maybe_unused]] libwebrtc::RTCPeerConnectionState state) {
    std::map<libwebrtc::RTCPeerConnectionState, std::string> map = {
        {libwebrtc::RTCPeerConnectionState::RTCPeerConnectionStateNew, "RTCPeerConnectionStateNew"},
        {libwebrtc::RTCPeerConnectionState::RTCPeerConnectionStateConnecting, "RTCPeerConnectionStateConnecting"},
        {libwebrtc::RTCPeerConnectionState::RTCPeerConnectionStateConnected, "RTCPeerConnectionStateConnected"},
        {libwebrtc::RTCPeerConnectionState::RTCPeerConnectionStateDisconnected, "RTCPeerConnectionStateDisconnected"},
        {libwebrtc::RTCPeerConnectionState::RTCPeerConnectionStateFailed, "RTCPeerConnectionStateFailed"},
        {libwebrtc::RTCPeerConnectionState::RTCPeerConnectionStateClosed, "RTCPeerConnectionStateClosed"}
    };
    PRIVMX_DEBUG("STREAMS", "API", _streamRoomId + ": ON PEER CONNECTION STATE " + map[state])
    if(_onPeerConnectionState.has_value()) _onPeerConnectionState.value()(state);
}
void PmxPeerConnectionObserver::OnIceGatheringState([[maybe_unused]] libwebrtc::RTCIceGatheringState state) {
    std::map<libwebrtc::RTCIceGatheringState, std::string> map = {
        {libwebrtc::RTCIceGatheringState::RTCIceGatheringStateNew, "RTCIceGatheringStateNew"},
        {libwebrtc::RTCIceGatheringState::RTCIceGatheringStateGathering, "RTCIceGatheringStateGathering"},
        {libwebrtc::RTCIceGatheringState::RTCIceGatheringStateComplete, "RTCIceGatheringStateComplete"}
    };
    PRIVMX_DEBUG("STREAMS", "API", _streamRoomId + ": ON ICE GATHERING STATE " + map[state])
    if(_onIceGatheringState.has_value()) _onIceGatheringState.value()(state);

}
void PmxPeerConnectionObserver::OnIceConnectionState([[maybe_unused]] libwebrtc::RTCIceConnectionState state) {
    std::map<libwebrtc::RTCIceConnectionState, std::string> map = {
        {libwebrtc::RTCIceConnectionState::RTCIceConnectionStateNew, "RTCIceConnectionStateNew"},
        {libwebrtc::RTCIceConnectionState::RTCIceConnectionStateChecking, "RTCIceConnectionStateChecking"},
        {libwebrtc::RTCIceConnectionState::RTCIceConnectionStateCompleted, "RTCIceConnectionStateCompleted"},
        {libwebrtc::RTCIceConnectionState::RTCIceConnectionStateConnected, "RTCIceConnectionStateConnected"},
        {libwebrtc::RTCIceConnectionState::RTCIceConnectionStateFailed, "RTCIceConnectionStateFailed"},
        {libwebrtc::RTCIceConnectionState::RTCIceConnectionStateDisconnected, "RTCIceConnectionStateDisconnected"},
        {libwebrtc::RTCIceConnectionState::RTCIceConnectionStateClosed, "RTCIceConnectionStateClosed"},
        {libwebrtc::RTCIceConnectionState::RTCIceConnectionStateMax, "RTCIceConnectionStateMax"}
    };
    PRIVMX_DEBUG("STREAMS", "API", _streamRoomId + ": ON ICE CONNECTION STATE " + map[state])
    if(_onIceConnectionState.has_value()) _onIceConnectionState.value()(state);
}
void PmxPeerConnectionObserver::OnIceCandidate([[maybe_unused]] libwebrtc::scoped_refptr<libwebrtc::RTCIceCandidate> candidate) {
    if(_onIceCandidate.has_value()) _onIceCandidate.value()(candidate);
}
void PmxPeerConnectionObserver::OnAddStream(libwebrtc::scoped_refptr<libwebrtc::RTCMediaStream> stream) {
    PRIVMX_DEBUG("STREAMS", "API", _streamRoomId + ": STREAM ADDED")
    PRIVMX_DEBUG("STREAMS", "API", "stream->video_tracks().size() -> " + std::to_string(stream->video_tracks().size()))
    PRIVMX_DEBUG("STREAMS", "API", "stream->audio_tracks().size() -> " + std::to_string(stream->audio_tracks().size()))
    PRIVMX_DEBUG("STREAMS", "API", "_onFrameCallback.has_value() -> " + std::to_string(_onFrameCallback.has_value()))
    if(_onFrameCallback.has_value()) {
        for(size_t i = 0; i < stream->video_tracks().size(); i++) { 
            auto track = stream->video_tracks()[i];
            RTCVideoRendererImpl<libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame>>* r {
                new RTCVideoRendererImpl<libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame>>(_onFrameCallback.value(), _streamRoomId + "-" + track->id().std_string())
            };
            PRIVMX_DEBUG("STREAMS", "API", "stream->video_tracks()[i] -> AddRenderer(r)")
            track->AddRenderer(r);
        }
    }
    if(_onAddStream.has_value()) _onAddStream.value()(stream);
}
void PmxPeerConnectionObserver::OnRemoveStream([[maybe_unused]] libwebrtc::scoped_refptr<libwebrtc::RTCMediaStream> stream) {
    PRIVMX_DEBUG("STREAMS", "API", _streamRoomId + ": ON REMOVE STREAM")
    if(_onRemoveStream.has_value()) _onRemoveStream.value()(stream);
}
void PmxPeerConnectionObserver::OnDataChannel([[maybe_unused]] libwebrtc::scoped_refptr<libwebrtc::RTCDataChannel> data_channel) {
    if(_onDataChannel.has_value()) _onDataChannel.value()(data_channel);
}
void PmxPeerConnectionObserver::OnRenegotiationNeeded() {
    PRIVMX_DEBUG("STREAMS", "API", _streamRoomId + ": ON RENEGOTIATION NEEDED")
    if(_onRenegotiationNeeded.has_value()) _onRenegotiationNeeded.value()();
};

void PmxPeerConnectionObserver::OnTrack([[maybe_unused]] libwebrtc::scoped_refptr<libwebrtc::RTCRtpTransceiver> transceiver) {
    PRIVMX_DEBUG("STREAMS", "API", _streamRoomId + ": ON TRACK")
    if(_onTrack.has_value()) _onTrack.value()(transceiver);
}
void PmxPeerConnectionObserver::OnAddTrack([[maybe_unused]] libwebrtc::vector<libwebrtc::scoped_refptr<libwebrtc::RTCMediaStream>> streams, [[maybe_unused]] libwebrtc::scoped_refptr<libwebrtc::RTCRtpReceiver> receiver) {
    PRIVMX_DEBUG("STREAMS", "API", _streamRoomId + ": TRACK ADDED")
    _frameCryptors.set(
        receiver->track()->id().std_string(), 
        privmx::webrtc::FrameCryptorFactory::frameCryptorFromRtpReceiver(_peerConnectionFactory ,receiver, _currentKeys, _options)
    );
    // for(size_t j = 0; j < streams.size(); j++) { 
    //     auto stream = streams[j];
    //     for(size_t i = 0; i < stream->video_tracks().size(); i++) { 
    //         if(stream->video_tracks()[i]->id().std_string() == receiver->track()->id().std_string()) {
    //             auto track = stream->video_tracks()[i];
    //             RTCVideoRendererImpl<libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame>>* r {
    //                 new RTCVideoRendererImpl<libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame>>(_onFrameCallback.value(), _streamRoomId + "-" + track->id().std_string())
    //             };
    //             PRIVMX_DEBUG("STREAMS", "API", "stream->video_tracks()[i] -> AddRenderer(r)")
    //             track->AddRenderer(r);
    //         }
    //     }
    // }
    if(_onAddTrack.has_value()) _onAddTrack.value()(streams, receiver);
}
void PmxPeerConnectionObserver::OnRemoveTrack([[maybe_unused]] libwebrtc::scoped_refptr<libwebrtc::RTCRtpReceiver> receiver) {
    PRIVMX_DEBUG("STREAMS", "API", _streamRoomId + ": ON REMOVE TRACK")
    _frameCryptors.erase(receiver->track()->id().std_string());
    if(_onRemoveTrack.has_value()) _onRemoveTrack.value()(receiver);
    if(receiver->media_type() == libwebrtc::RTCMediaType::VIDEO && _onRemoveVideoTrack.has_value()) _onRemoveVideoTrack.value()(_streamRoomId + "-" + receiver->track()->id().std_string());
}

void PmxPeerConnectionObserver::UpdateCurrentKeys(std::shared_ptr<privmx::webrtc::KeyStore> newKeys) {
    _currentKeys = newKeys;
    PRIVMX_DEBUG("STREAMS", "PmxPeerConnectionObserver", "PmxPeerConnectionObserver::UpdateCurrentKeys _frameCryptors.size()=" + std::to_string(_frameCryptors.size()));
    _frameCryptors.forAll([&]([[maybe_unused]]const std::string &id, const std::shared_ptr<privmx::webrtc::FrameCryptor> &frameCryptor) {
        PRIVMX_DEBUG("STREAMS", "PmxPeerConnectionObserver", "PmxPeerConnectionObserver::UpdateCurrentKeys::forAll::single");
        frameCryptor->setKeyStore(_currentKeys);
    });
}

void PmxPeerConnectionObserver::SetFrameCryptorOptions(privmx::webrtc::FrameCryptorOptions options) {
    _options = options;
    _frameCryptors.forAll([&]([[maybe_unused]]const std::string &id, const std::shared_ptr<privmx::webrtc::FrameCryptor> &frameCryptor) {
        frameCryptor->setOptions(_options);
    });
}


