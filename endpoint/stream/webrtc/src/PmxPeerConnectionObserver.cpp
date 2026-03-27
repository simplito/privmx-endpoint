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

PmxPeerConnectionObserver::PmxPeerConnectionObserver(
    libwebrtc::scoped_refptr<libwebrtc::RTCPeerConnectionFactory> peerConnectionFactory,
    const std::string& streamRoomId, 
    std::shared_ptr<privmx::webrtc::KeyStore> keys, 
    const privmx::webrtc::FrameCryptorOptions& options,
    std::shared_ptr<DataChannelMessageEncryptorV1> messageEncryptor
) : 
_peerConnectionFactory(peerConnectionFactory), 
_streamRoomId(streamRoomId), 
_currentKeys(keys), 
_options(options),
_messageEncryptor(messageEncryptor),
_roomOnTrackInterface(nullptr),
_streamOnTrackInterfacesMap(std::make_shared<privmx::utils::ThreadSaveMap<std::string, std::shared_ptr<OnTrackInterface>>>()) {}

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
    LOG_DEBUG("STREAMS ", "API ", _streamRoomId + ": ON ICE CANDIDATE")
    if(_onIceCandidate.has_value()) _onIceCandidate.value()(candidate);
}
void PmxPeerConnectionObserver::OnAddStream(libwebrtc::scoped_refptr<libwebrtc::RTCMediaStream> stream) {
    LOG_DEBUG("STREAMS ", "API ", _streamRoomId + ": STREAM ADDED")
    LOG_DEBUG("STREAMS ", "API ", "stream->video_tracks().size() -> " + std::to_string(stream->video_tracks().size()))
    LOG_DEBUG("STREAMS ", "API ", "stream->audio_tracks().size() -> " + std::to_string(stream->audio_tracks().size()))
}
void PmxPeerConnectionObserver::OnRemoveStream([[maybe_unused]] libwebrtc::scoped_refptr<libwebrtc::RTCMediaStream> stream) {
    LOG_DEBUG("STREAMS ", "API ", _streamRoomId + ": ON REMOVE STREAM")
}
void PmxPeerConnectionObserver::OnDataChannel(libwebrtc::scoped_refptr<libwebrtc::RTCDataChannel> data_channel) {
    LOG_DEBUG("STREAMS ", "API ", _streamRoomId + ": ON DATA CHANNEL channel_label: ", data_channel->label().std_string())
    std::shared_ptr<stream::OnTrackInterface> roomOnTrackInterface = nullptr;
    {
        std::shared_lock<std::shared_mutex> lock(_onTrackInterfaceMutex);
        if(_roomOnTrackInterface) roomOnTrackInterface = _roomOnTrackInterface;
    }
    std::shared_ptr<DataChannelImpl> dataChannelImpl = std::make_shared<DataChannelImpl>(roomOnTrackInterface, _messageEncryptor, data_channel);
    _dataChannels.set(data_channel->label().std_string(), dataChannelImpl);
}
void PmxPeerConnectionObserver::OnRenegotiationNeeded() {
    LOG_DEBUG("STREAMS ", "API ", _streamRoomId + ": ON RENEGOTIATION NEEDED")
};

void PmxPeerConnectionObserver::OnTrack([[maybe_unused]] libwebrtc::scoped_refptr<libwebrtc::RTCRtpTransceiver> transceiver) {
    LOG_DEBUG("STREAMS ", "API ", _streamRoomId + ": ON TRACK")
    LOG_TRACE("STREAMS ", "API ", _streamRoomId + ": ON TRACK done")
}
void PmxPeerConnectionObserver::OnAddTrack([[maybe_unused]] libwebrtc::vector<libwebrtc::scoped_refptr<libwebrtc::RTCMediaStream>> streams, [[maybe_unused]] libwebrtc::scoped_refptr<libwebrtc::RTCRtpReceiver> receiver) {
    LOG_DEBUG("STREAMS ", "API ", _streamRoomId + ": ON ADD TRACK")    
    // set frame crypto to decrypt track
    _frameCryptors.set(
        receiver->track()->id().std_string(), 
        privmx::webrtc::FrameCryptorFactory::frameCryptorFromRtpReceiver(_peerConnectionFactory ,receiver, _currentKeys, _options)
    );

    DataType dataType = receiver->track()->kind().std_string() == "video" ? DataType::VIDEO : DataType::AUDIO;
    auto track = receiver->track();
    std::vector<std::string> streamIds;
    LOG_TRACE("PmxPeerConnectionObserver::OnAddTrack streamIds.size(): ", receiver->stream_ids().std_vector().size())
    for(const auto& streamId: receiver->stream_ids().std_vector()) {
        LOG_TRACE("PmxPeerConnectionObserver::OnAddTrack streamId: ", streamId.std_string())
        streamIds.push_back(streamId.std_string());
    }
    // Room interface
    std::shared_ptr<privmx::endpoint::stream::OnTrackInterface> roomOnTrackInterface = nullptr;
    {
        std::shared_lock<std::shared_mutex> lock(_onTrackInterfaceMutex);
        if(_roomOnTrackInterface) roomOnTrackInterface = _roomOnTrackInterface;
    }
    // callback OnRemoteTrack
    for(const auto& stream: streams.std_vector()) {
        auto tmp = _streamOnTrackInterfacesMap->get(stream->id().std_string());
        if(tmp.has_value()) {
            tmp.value()->OnRemoteTrack(Track{dataType, streamIds, track->id().std_string(), !track->enabled(), [track](bool mute) {return track->set_enabled(!mute);}}, TrackAction::ADDED);
        }
    }
    if(roomOnTrackInterface) {
        roomOnTrackInterface->OnRemoteTrack(Track{dataType, streamIds, track->id().std_string(), !track->enabled(), [track](bool mute) {return track->set_enabled(!mute);}}, TrackAction::ADDED);
    }
    // callback on data
    if(dataType == DataType::VIDEO) {
        auto videoTrack = static_cast<libwebrtc::RTCVideoTrack*>(track.get());
        std::shared_ptr<RTCVideoRendererImpl> renderer = 
            std::make_shared<RTCVideoRendererImpl>(
                roomOnTrackInterface, _streamOnTrackInterfacesMap, streamIds, track
            );
        _RTCVideoRenderers.set(videoTrack->id().std_string(), renderer);
        videoTrack->AddRenderer(renderer.get());
    } else if(dataType == DataType::AUDIO) {
        auto audioTrack = static_cast<libwebrtc::RTCAudioTrack*>(track.get());
        std::shared_ptr<AudioTrackSinkImpl> sink = 
            std::make_shared<AudioTrackSinkImpl>(
                roomOnTrackInterface, _streamOnTrackInterfacesMap, streamIds, track
            );
        _audioTrackSinks.set(audioTrack->id().std_string(), sink);
        audioTrack->SetSink(sink);
    };
    LOG_TRACE("STREAMS ", "API ", _streamRoomId + ": ON ADD TRACK done")
}

void PmxPeerConnectionObserver::OnRemoveTrack([[maybe_unused]] libwebrtc::scoped_refptr<libwebrtc::RTCRtpReceiver> receiver) {
    LOG_DEBUG("STREAMS ", "API ", _streamRoomId + ": ON REMOVE TRACK")
    DataType dataType = receiver->track()->kind().std_string() == "video" ? DataType::VIDEO : DataType::AUDIO;
    auto streams = receiver->streams();
    auto track = receiver->track();
    std::vector<std::string> streamIds;
    for(const auto& streamId: receiver->stream_ids().std_vector()) streamIds.push_back(streamId.std_string());
    // callback on track
    for(const auto& stream: streams.std_vector()) {
        auto tmp = _streamOnTrackInterfacesMap->get(stream->id().std_string());
        if(tmp.has_value()) {
            tmp.value()->OnRemoteTrack(Track{dataType, streamIds, track->id().std_string(), !track->enabled(), [track](bool mute) {return track->set_enabled(!mute);}}, TrackAction::ADDED);
        }
    }
    if(dataType == DataType::AUDIO) _audioTrackSinks.erase(receiver->track()->id().std_string());
    if(dataType == DataType::VIDEO) _RTCVideoRenderers.erase(receiver->track()->id().std_string());
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

void PmxPeerConnectionObserver::setOnTrackInterface(std::shared_ptr<OnTrackInterface> roomOnTrackInterface) {
    std::unique_lock<std::shared_mutex> lock(_onTrackInterfaceMutex);
    _roomOnTrackInterface = roomOnTrackInterface;
    _RTCVideoRenderers.forAll([roomOnTrackInterface]([[maybe_unused]] const std::string& streamId, const std::shared_ptr<privmx::endpoint::stream::RTCVideoRendererImpl>& renderer) {
        renderer->updateRoomOnTrackInterface(roomOnTrackInterface);
    });
    _audioTrackSinks.forAll([roomOnTrackInterface]([[maybe_unused]] const std::string& streamId, const std::shared_ptr<privmx::endpoint::stream::AudioTrackSinkImpl>& renderer) {
        renderer->updateRoomOnTrackInterface(roomOnTrackInterface);
    });
    _dataChannels.forAll([roomOnTrackInterface]([[maybe_unused]] const std::string& trackId, const std::shared_ptr<DataChannelImpl>& renderer) {
        renderer->updateOnTrackInterface(roomOnTrackInterface);
    });
}
void PmxPeerConnectionObserver::addOnTrackInterfaceForSingleStream(const std::string& streamId, std::shared_ptr<OnTrackInterface> streamOnTrackInterface) {
    _streamOnTrackInterfacesMap->set(streamId, streamOnTrackInterface);
}

void PmxPeerConnectionObserver::removeOnTrackInterfaceFormSingleStream(const std::string& streamId) {
    _streamOnTrackInterfacesMap->erase(streamId);
}
