/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/
#include "../include/privmx/endpoint/stream/PmxPeerConnectionObserver.hpp"

#include <rtc_video_frame.h>
#include <thread>

#include <iostream>
#include <memory>
#include <privmx/utils/Logger.hpp>

#include "privmx/endpoint/stream/PmxPeerConnectionObserver.hpp"

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

    auto streamTracks = stream->tracks();
    if (streamTracks.size() < 1) {
        printf("NO stream tracks...");
        exit(0);
    }
    for(size_t i = 0; i < streamTracks.size(); i++) {
        auto track = streamTracks[i];
        auto trackKind = track->kind().std_string();
        if (trackKind.compare("video")) {
            printf("\n\n\n\n\n\n\n\n!!!!!!!!!!!!!!!!!!!! Detected new VIDEO track\n\n\n\n\n\n\n\n\n");
            auto video_track = static_cast<libwebrtc::RTCVideoTrack*>(track.get());

            // RTCVideoRendererImpl<libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame>>* r {
            //     new RTCVideoRendererImpl<libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame>>(_onFrameCallback.value(), _streamRoomId + "-" + track->id().std_string())
            // };
            TrackRenderer trackRenderer = {
                .renderer = new RTCVideoRendererImpl<libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame>>(_onFrameCallback.value(), _streamRoomId + "-" + track->id().std_string()),
                .trackId = track->id().std_string()
            };
            _trackRenderers.push_back(trackRenderer);

            video_track->AddRenderer(trackRenderer.renderer);
            printf("added renderer for track %s", &track->id().std_string()[0]);
            std::cout << "track state: " << video_track->state() << "/ enabled: " << video_track->enabled() << std::endl;
        }
    }



    // LOG_DEBUG("STREAMS ", "API ", "stream->video_tracks().size() -> " + std::to_string(stream->video_tracks().size()))
    // LOG_DEBUG("STREAMS ", "API ", "stream->audio_tracks().size() -> " + std::to_string(stream->audio_tracks().size()))
    // LOG_DEBUG("STREAMS ", "API ", "_onFrameCallback.has_value() -> " + std::to_string(_onFrameCallback.has_value()))
    // _tmp_stream = stream;
    // for(size_t i = 0; i < _tmp_stream.value()->video_tracks().size(); i++) {
    //     auto track = _tmp_stream.value()->video_tracks()[i];
    //     LOG_TRACE("STREAMS ", "API ", "OnAddStream->video_tracks()[" + std::to_string(i) +"]");
    //     LOG_TRACE("track: ", track.get());
    //     LOG_TRACE("track->state(): ", track->state());
    //     LOG_TRACE("track->id(): ", track->id().std_string());
    //     LOG_TRACE("track->enabled(): ", track->enabled());
    //     if(_onFrameCallback.has_value()) {
    //     RTCVideoRendererImpl<libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame>>* r {
    //         new RTCVideoRendererImpl<libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame>>(_onFrameCallback.value(), _streamRoomId + "-" + track->id().std_string())
    //     };
    //     LOG_DEBUG("STREAMS ", "API ", "stream->video_tracks()[i] -> AddRenderer(r)")
    //     track->AddRenderer(r);
    //     }
    // }
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
    // auto receiver = transceiver->receiver();
    // // set frame crypto to decrypt track
    // _frameCryptors.set(
    //     receiver->track()->id().std_string(),
    //     privmx::webrtc::FrameCryptorFactory::frameCryptorFromRtpReceiver(_peerConnectionFactory ,receiver, _currentKeys, _options)
    // );
    //
    // auto track = receiver->track();
    // if (!track) return;
    //
    // auto trackKind = track->kind().std_string();
    // if (trackKind.compare("video")) {
    //     printf("!!!!!!!!!!!!!!!!!!!! Detected new VIDEO track\n");
    //
    //     auto video_track = static_cast<libwebrtc::RTCVideoTrack*>(track.get());
    //
    //     // RTCVideoRendererImpl<libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame>>* r {
    //     //     new RTCVideoRendererImpl<libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame>>(_onFrameCallback.value(), _streamRoomId + "-" + track->id().std_string())
    //     // };
    //     TrackRenderer trackRenderer = {
    //         .renderer = new RTCVideoRendererImpl<libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame>>(_onFrameCallback.value(), _streamRoomId + "-" + track->id().std_string()),
    //         .transceiver = transceiver
    //     };
    //     _trackRenderers.push_back(trackRenderer);
    //
    //     video_track->AddRenderer(trackRenderer.renderer);
    //     printf("added renderer");
    //     std::cout << "track state: " << video_track->state() << "/ enabled: " << video_track->enabled() << std::endl;
    // }

}
void PmxPeerConnectionObserver::OnAddTrack([[maybe_unused]] libwebrtc::vector<libwebrtc::scoped_refptr<libwebrtc::RTCMediaStream>> streams, [[maybe_unused]] libwebrtc::scoped_refptr<libwebrtc::RTCRtpReceiver> receiver) {
    LOG_DEBUG("STREAMS ", "API ", _streamRoomId + ": ON ADD TRACK")
    _frameCryptors.set(
        receiver->track()->id().std_string(),
        privmx::webrtc::FrameCryptorFactory::frameCryptorFromRtpReceiver(_peerConnectionFactory ,receiver, _currentKeys, _options)
    );


    // set frame crypto to decrypt track
    // _frameCryptors.set(
    //     receiver->track()->id().std_string(),
    //     privmx::webrtc::FrameCryptorFactory::frameCryptorFromRtpReceiver(_peerConnectionFactory ,receiver, _currentKeys, _options)
    // );
    // // callback on track
    // if(_onTrack.has_value()) {
    //     _onTrack.value()(_streamRoomId + "-" + receiver->track()->id().std_string());
    // }
    // if(_tmp_stream.has_value()) {
    //     LOG_TRACE("video_tracks().size(): ", _tmp_stream.value()->video_tracks().size());
    //     LOG_TRACE("audio_tracks().size(): ", _tmp_stream.value()->audio_tracks().size());
    //     for(size_t i = 0; i < _tmp_stream.value()->video_tracks().size(); i++) {
    //         auto track = _tmp_stream.value()->video_tracks()[i];
    //         LOG_TRACE("STREAMS ", "API ", "OnAddStream->video_tracks()[" + std::to_string(i) +"]");
    //         LOG_TRACE("track: ", track.get());
    //         LOG_TRACE("track->state(): ", track->state());
    //         LOG_TRACE("track->id(): ", track->id().std_string());
    //         LOG_TRACE("track->enabled(): ", track->enabled());
    //         if(_onFrameCallback.has_value()) {
    //         // RTCVideoRendererImpl<libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame>>* r {
    //         //     new RTCVideoRendererImpl<libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame>>(_onFrameCallback.value(), _streamRoomId + "-" + track->id().std_string())
    //         // };
    //         RTCVideoRendererImpl<libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame>>* r {
    //             new RTCVideoRendererImpl<libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame>>([](int64_t, int64_t, std::shared_ptr<Frame>, const std::string&){std::cout << "h1" << std::endl;}, _streamRoomId + "-" + track->id().std_string())
    //         };
    //         LOG_DEBUG("STREAMS ", "API ", "stream->video_tracks()[i] -> AddRenderer(r)")
    //         track->AddRenderer(r);
    //         }
    //     }
    // }




    // auto track = receiver->track();
    // if(track->kind().std_string() == "video" && _onFrameCallback.has_value()) {
    //     auto cast_track = static_cast<libwebrtc::RTCVideoTrack*>(track.get());
    //     LOG_TRACE("track: ", track.get());
    //     LOG_TRACE("cast_track: ", cast_track);
    //     LOG_TRACE("track->state(): ", cast_track->state());
    //     LOG_TRACE("track->id(): ", cast_track->id().std_string());
    //     LOG_TRACE("track->enabled(): ", cast_track->enabled());
    //     RTCVideoRendererImpl<libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame>>* r {
    //         new RTCVideoRendererImpl<libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame>>([](int64_t, int64_t, std::shared_ptr<Frame>, const std::string&){std::cout << "h1" << std::endl;}, _streamRoomId + "-" + track->id().std_string())
    //     };
    //    cast_track->AddRenderer(r);
    // }

    // set on frame renderer (videoTrack)
    // for(size_t j = 0; j < streams.size(); j++) {
    //     auto stream = streams[j];
    //     std::cout << "streamId: " << stream->id().std_string() << std::endl; 
    //     std::cout << "receiver->track(): " << receiver->track()->id().std_string() << std::endl; 
    //     std::cout << "receiver->kind(): " << receiver->track()->kind().std_string() << std::endl; 
    //     auto track = stream->FindVideoTrack(receiver->track()->id());
    //     if(track != nullptr && _onFrameCallback.has_value() ) {
    //         RTCVideoRendererImpl<libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame>>* r {
    //             new RTCVideoRendererImpl<libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame>>([](int64_t, int64_t, std::shared_ptr<Frame>, const std::string&){std::cout << "h1" << std::endl;}, _streamRoomId + "-" + track->id().std_string())
    //         };
    //         LOG_DEBUG("STREAMS ", "API ", "stream->FindVideoTrack(" + receiver->track()->id().std_string() +") -> AddRenderer(r)")
    //         std::cout << "track: " << track.get() << std::endl;
    //         std::cout << "track->state(): " << track->state() << std::endl;
    //         std::cout << "track->id(): " << track->id().std_string() << std::endl;
    //         std::cout << "track->enabled(): " << track->enabled() << std::endl;
    //         track->AddRenderer(r);
    //     }
    // }
    
}

void PmxPeerConnectionObserver::OnRemoveTrack([[maybe_unused]] libwebrtc::scoped_refptr<libwebrtc::RTCRtpReceiver> receiver) {
    LOG_DEBUG("STREAMS ", "API ", _streamRoomId + ": ON REMOVE TRACK")
    _frameCryptors.erase(receiver->track()->id().std_string());
    if(receiver->media_type() == libwebrtc::RTCMediaType::VIDEO && _onRemoveTrack.has_value()) {
        _onRemoveTrack.value()(_streamRoomId + "-" + receiver->track()->id().std_string());
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


