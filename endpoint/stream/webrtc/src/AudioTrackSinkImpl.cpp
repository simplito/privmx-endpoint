/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/stream/AudioTrackSinkImpl.hpp"
#include <privmx/utils/Logger.hpp>

using namespace privmx::endpoint::stream; 

AudioTrackSinkImpl::AudioTrackSinkImpl(
    std::shared_ptr<OnTrackInterface> roomOnTrackInterface,
    std::shared_ptr<privmx::utils::ThreadSaveMap<std::string, std::shared_ptr<OnTrackInterface>>> streamOnTrackInterfacesMap, 
    const std::vector<std::string>& streamIds, 
    libwebrtc::scoped_refptr<libwebrtc::RTCMediaTrack> track
) : 
    _roomOnTrackInterface(roomOnTrackInterface), _streamOnTrackInterfacesMap(streamOnTrackInterfacesMap), _streamIds(streamIds), _track(track) {
    LOG_TRACE("AudioTrackSinkImpl created")
}
AudioTrackSinkImpl::AudioTrackSinkImpl(const std::vector<std::string>& streamIds, libwebrtc::scoped_refptr<libwebrtc::RTCMediaTrack> track) 
: _roomOnTrackInterface(nullptr), _streamOnTrackInterfacesMap(nullptr), _streamIds(streamIds), _track(track) {
    LOG_TRACE("AudioTrackSinkImpl created")
}
AudioTrackSinkImpl::~AudioTrackSinkImpl() {
    LOG_TRACE("AudioTrackSinkImpl destroyed")
}
void AudioTrackSinkImpl::updateRoomOnTrackInterface(std::shared_ptr<OnTrackInterface> roomOnTrackInterface) {
    std::unique_lock<std::mutex> lock(m);
    _roomOnTrackInterface = roomOnTrackInterface;
}
void AudioTrackSinkImpl::updateStreamOnTrackInterfacesMap(std::shared_ptr<privmx::utils::ThreadSaveMap<std::string, std::shared_ptr<OnTrackInterface>>> streamOnTrackInterfacesMap) {
    std::unique_lock<std::mutex> lock(m);
    _streamOnTrackInterfacesMap = streamOnTrackInterfacesMap;
}
void AudioTrackSinkImpl::OnData(const void* audio_data, int bits_per_sample, int sample_rate, size_t number_of_channels, size_t number_of_frames) {
    std::unique_lock<std::mutex> lock(m);
    std::shared_ptr<AudioData> audioData = std::make_unique<AudioData>(DataType::AUDIO, _streamIds, _track->id().std_string(), audio_data, bits_per_sample, sample_rate, number_of_channels, number_of_frames);
    if(_roomOnTrackInterface) {
        _roomOnTrackInterface->OnData(audioData);
    }
    if(_streamOnTrackInterfacesMap) {
        for(const auto& streamId: _streamIds) {
            auto OnTrackInterface = _streamOnTrackInterfacesMap->get(streamId);
            if(OnTrackInterface) {
                OnTrackInterface.value()->OnData(audioData);
            }
        }
    }
}