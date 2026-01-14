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
#include <privmx/utils/Logger.hpp>


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
    LOG_DEBUG("STREAMS ", "API ", _streamRoomId + ": ON SIGNALING STATE " + map[state])
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
    LOG_DEBUG("STREAMS ", "API ", _streamRoomId + ": ON PEER CONNECTION STATE " + map[state])
}
void PmxPeerConnectionObserver::OnIceGatheringState([[maybe_unused]] libwebrtc::RTCIceGatheringState state) {
    std::map<libwebrtc::RTCIceGatheringState, std::string> map = {
        {libwebrtc::RTCIceGatheringState::RTCIceGatheringStateNew, "RTCIceGatheringStateNew"},
        {libwebrtc::RTCIceGatheringState::RTCIceGatheringStateGathering, "RTCIceGatheringStateGathering"},
        {libwebrtc::RTCIceGatheringState::RTCIceGatheringStateComplete, "RTCIceGatheringStateComplete"}
    };
    LOG_DEBUG("STREAMS ", "API ", _streamRoomId + ": ON ICE GATHERING STATE " + map[state])

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
    LOG_DEBUG("STREAMS ", "API ", _streamRoomId + ": ON ICE CONNECTION STATE " + map[state])
}
void PmxPeerConnectionObserver::OnIceCandidate([[maybe_unused]] libwebrtc::scoped_refptr<libwebrtc::RTCIceCandidate> candidate) {
    if(_onIceCandidate.has_value()) _onIceCandidate.value()(candidate);
}
void PmxPeerConnectionObserver::OnAddStream(libwebrtc::scoped_refptr<libwebrtc::RTCMediaStream> stream) {
    LOG_DEBUG("STREAMS ", "API ", _streamRoomId + ": STREAM ADDED")
    LOG_DEBUG("STREAMS ", "API ", "stream->video_tracks().size() -> " + std::to_string(stream->video_tracks().size()))
    LOG_DEBUG("STREAMS ", "API ", "stream->audio_tracks().size() -> " + std::to_string(stream->audio_tracks().size()))
    _tmp_stream = stream;
    for(size_t i = 0; i < _tmp_stream.value()->video_tracks().size(); i++) { 
        auto track = _tmp_stream.value()->video_tracks()[i];
        LOG_TRACE("ON_ADD_TRACK: STREAMS ", "API ", "OnAddStream->video_tracks()[" + std::to_string(i) +"]");
        if(_onTrackInterface) {
            LOG_DEBUG("STREAMS ", "API ", "stream->video_tracks()[i] -> AddRenderer(r)")
            RTCVideoRendererImpl<libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame>>* r1 {
                new RTCVideoRendererImpl<libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame>>(
                    _onTrackInterface, _tmp_stream.value()->id().std_string(), track->id().std_string()
                )
            };
            track->AddRenderer(r1);
        }
    }
    for(size_t i = 0; i < _tmp_stream.value()->audio_tracks().size(); i++) { 
        auto track = _tmp_stream.value()->audio_tracks()[i];
        LOG_TRACE("ON_ADD_TRACK: STREAMS ", "API ", "OnAddStream->audio_tracks()[" + std::to_string(i) +"]");
        if(_onTrackInterface) {
            LOG_DEBUG("STREAMS ", "API ", "stream->audio_tracks()[i] -> SetSink(r)")
            std::shared_ptr<AudioTrackSinkImpl> s1 = std::make_shared<AudioTrackSinkImpl> (
                _onTrackInterface, _tmp_stream.value()->id().std_string(), track->id().std_string()
            );
            track->SetSink(s1);
        }
    }
}
void PmxPeerConnectionObserver::OnRemoveStream([[maybe_unused]] libwebrtc::scoped_refptr<libwebrtc::RTCMediaStream> stream) {
    LOG_DEBUG("STREAMS ", "API ", _streamRoomId + ": ON REMOVE STREAM")
}
void PmxPeerConnectionObserver::OnDataChannel([[maybe_unused]] libwebrtc::scoped_refptr<libwebrtc::RTCDataChannel> data_channel) {
    LOG_DEBUG("STREAMS ", "API ", _streamRoomId + ": ON DATA CHANNEL")
}
void PmxPeerConnectionObserver::OnRenegotiationNeeded() {
    LOG_DEBUG("STREAMS ", "API ", _streamRoomId + ": ON RENEGOTIATION NEEDED")
};

void PmxPeerConnectionObserver::OnTrack([[maybe_unused]] libwebrtc::scoped_refptr<libwebrtc::RTCRtpTransceiver> transceiver) {
    LOG_DEBUG("STREAMS ", "API ", _streamRoomId + ": ON TRACK")

}
void PmxPeerConnectionObserver::OnAddTrack([[maybe_unused]] libwebrtc::vector<libwebrtc::scoped_refptr<libwebrtc::RTCMediaStream>> streams, [[maybe_unused]] libwebrtc::scoped_refptr<libwebrtc::RTCRtpReceiver> receiver) {
    LOG_DEBUG("STREAMS ", "API ", _streamRoomId + ": ON ADD TRACK")    
    // set frame crypto to decrypt track
    _frameCryptors.set(
        receiver->track()->id().std_string(), 
        privmx::webrtc::FrameCryptorFactory::frameCryptorFromRtpReceiver(_peerConnectionFactory ,receiver, _currentKeys, _options)
    );
    // callback on track
    if(_onTrackInterface) {
        DataType dataType = receiver->track()->kind().std_string() == "video" ? DataType::VIDEO : DataType::AUDIO;
        _onTrackInterface->OnRemoteTrack(Track{dataType, receiver->track()->id().std_string(), !receiver->track()->enabled()}, TrackAction::ADDED);
    }
    if(_tmp_stream.has_value()) {
        LOG_TRACE("ON_ADD_TRACK: video_tracks().size(): ", _tmp_stream.value()->video_tracks().size());
        LOG_TRACE("ON_ADD_TRACK: audio_tracks().size(): ", _tmp_stream.value()->audio_tracks().size());
        for(size_t i = 0; i < _tmp_stream.value()->video_tracks().size(); i++) { 
            auto track = _tmp_stream.value()->video_tracks()[i];
            LOG_TRACE("ON_ADD_TRACK: STREAMS ", "API ", "OnAddStream->video_tracks()[" + std::to_string(i) +"]");
            LOG_TRACE("ON_ADD_TRACK: track: ", track.get());
            LOG_TRACE("ON_ADD_TRACK: track->state(): ", track->state());
            LOG_TRACE("ON_ADD_TRACK: track->id(): ", track->id().std_string());
            LOG_TRACE("ON_ADD_TRACK: track->enabled(): ", track->enabled());
            if(_onTrackInterface) {
                LOG_DEBUG("STREAMS ", "API ", "stream->video_tracks()[i] -> AddRenderer(r)")
                RTCVideoRendererImpl<libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame>>* r1 {
                    new RTCVideoRendererImpl<libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame>>(
                        _onTrackInterface, _tmp_stream.value()->id().std_string(), track->id().std_string()
                    )
                };
                track->AddRenderer(r1);
            }
        }
    }   
}

void PmxPeerConnectionObserver::OnRemoveTrack([[maybe_unused]] libwebrtc::scoped_refptr<libwebrtc::RTCRtpReceiver> receiver) {
    LOG_DEBUG("STREAMS ", "API ", _streamRoomId + ": ON REMOVE TRACK")
    _frameCryptors.erase(receiver->track()->id().std_string());
    if(_onTrackInterface) {
        DataType dataType = receiver->track()->kind().std_string() == "video" ? DataType::VIDEO : DataType::AUDIO;
        _onTrackInterface->OnRemoteTrack(Track{dataType, receiver->track()->id().std_string(), !receiver->track()->enabled()}, TrackAction::ADDED);
    }
}

void PmxPeerConnectionObserver::UpdateCurrentKeys(std::shared_ptr<privmx::webrtc::KeyStore> newKeys) {
    _currentKeys = newKeys;
    LOG_DEBUG("STREAMS", "PmxPeerConnectionObserver", "PmxPeerConnectionObserver::UpdateCurrentKeys _frameCryptors.size()=" + std::to_string(_frameCryptors.size()));
    _frameCryptors.forAll([&]([[maybe_unused]]const std::string &id, const std::shared_ptr<privmx::webrtc::FrameCryptor> &frameCryptor) {
        LOG_DEBUG("STREAMS", "PmxPeerConnectionObserver", "PmxPeerConnectionObserver::UpdateCurrentKeys::forAll::single");
        frameCryptor->setKeyStore(_currentKeys);
    });
}

void PmxPeerConnectionObserver::SetFrameCryptorOptions(privmx::webrtc::FrameCryptorOptions options) {
    _options = options;
    _frameCryptors.forAll([&]([[maybe_unused]]const std::string &id, const std::shared_ptr<privmx::webrtc::FrameCryptor> &frameCryptor) {
        frameCryptor->setOptions(_options);
    });
}

void PmxPeerConnectionObserver::setOnTrackInterface(std::shared_ptr<OnTrackInterface> onTrackInterface) {
    _onTrackInterface = onTrackInterface;
}

