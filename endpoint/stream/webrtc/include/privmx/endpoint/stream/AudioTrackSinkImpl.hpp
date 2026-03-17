/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_WEBRTC_AUDIO_TRACK_SINK_IMPL_HPP_
#define _PRIVMXLIB_ENDPOINT_WEBRTC_AUDIO_TRACK_SINK_IMPL_HPP_

#include <string>
#include <libwebrtc.h>
#include <rtc_audio_track.h>
#include "privmx/endpoint/stream/webrtc/Types.hpp"
#include "privmx/endpoint/stream/webrtc/OnTrackInterface.hpp"
#include <privmx/utils/ThreadSaveMap.hpp>

namespace privmx {
namespace endpoint {
namespace stream {

class AudioTrackSinkImpl : public libwebrtc::AudioTrackSink {
public:
    AudioTrackSinkImpl(
        std::shared_ptr<OnTrackInterface> roomOnTrackInterface,
        std::shared_ptr<privmx::utils::ThreadSaveMap<std::string, std::shared_ptr<OnTrackInterface>>> streamOnTrackInterfacesMap, 
        const std::vector<std::string>& streamIds, 
        libwebrtc::scoped_refptr<libwebrtc::RTCMediaTrack> track
    );
    AudioTrackSinkImpl(const std::vector<std::string>& streamIds, libwebrtc::scoped_refptr<libwebrtc::RTCMediaTrack> track);
    ~AudioTrackSinkImpl();
    void updateRoomOnTrackInterface(std::shared_ptr<OnTrackInterface> roomOnTrackInterface);
    void updateStreamOnTrackInterfacesMap(std::shared_ptr<privmx::utils::ThreadSaveMap<std::string, std::shared_ptr<OnTrackInterface>>> streamOnTrackInterfacesMap);
    virtual void OnData(const void* audio_data, int bits_per_sample, int sample_rate, size_t number_of_channels, size_t number_of_frames) override;
private:
    std::mutex m;
    std::shared_ptr<OnTrackInterface> _roomOnTrackInterface;
    std::shared_ptr<privmx::utils::ThreadSaveMap<std::string, std::shared_ptr<OnTrackInterface>>> _streamOnTrackInterfacesMap;
    std::vector<std::string> _streamIds;
    libwebrtc::scoped_refptr<libwebrtc::RTCMediaTrack> _track;
};

} // stream
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_WEBRTC_AUDIO_TRACK_SINK_IMPL_HPP_
