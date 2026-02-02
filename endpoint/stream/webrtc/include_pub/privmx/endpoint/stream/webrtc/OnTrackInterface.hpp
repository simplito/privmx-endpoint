#ifndef _PRIVMXLIB_ENDPOINT_STREAM_ONTRACKINTERFACE_HPP
#define _PRIVMXLIB_ENDPOINT_STREAM_ONTRACKINTERFACE_HPP

#include <string>
#include <optional>
#include "privmx/endpoint/stream/webrtc/Types.hpp"
#include <privmx/endpoint/stream/Types.hpp>

namespace privmx {
namespace endpoint {
namespace stream {

enum TrackAction {
    REMOVED,
    ADDED
};
enum DataType {
    VIDEO,
    AUDIO,
    PLAIN
};
struct Track {
    DataType kind;
    std::vector<std::string> streamIds;
    std::string trackId;
    bool muted;
    std::function<void(bool)> updateMute;
};
struct TrackEvent {
    std::string id;
    std::optional<Track> track;
    Stream stream;
};
struct Data {
    Data(DataType _type, const std::vector<std::string>& _streamIds, const std::string& _track) 
        : type(_type), streamIds(_streamIds), track(_track) {}
    virtual ~Data() = default;
    DataType type;
    const std::vector<std::string> streamIds;
    const std::string track;
};
struct VideoData : public Data {
    VideoData(const std::vector<std::string>& _streamIds, const std::string& _track, const int64_t _w,  const int64_t _h, std::shared_ptr<Frame> _frameData ) 
        : Data(DataType::VIDEO, _streamIds, _track), w(_w), h(_h), frameData(_frameData) {}
    const int64_t w; 
    const int64_t h; 
    std::shared_ptr<Frame> frameData;
};
struct AudioData : public Data {
    AudioData(const std::vector<std::string>& _streamIds, const std::string& _track, const void* _audio_data, int _bits_per_sample, int _sample_rate, size_t _number_of_channels, size_t _number_of_frames) 
        : Data(DataType::AUDIO, _streamIds, _track), audio_data(_audio_data), bits_per_sample(_bits_per_sample), sample_rate(_sample_rate), number_of_channels(_number_of_channels), number_of_frames(_number_of_frames) {}
    const void* audio_data; 
    int bits_per_sample;
    int sample_rate;
    size_t number_of_channels; 
    size_t number_of_frames;
};
struct PlainData : public Data {
    PlainData(const std::vector<std::string>& _streamIds, const std::string& _track, const std::string& _data, bool _binary) 
        : Data(DataType::PLAIN, _streamIds, _track), data(_data), binary(_binary) {}
    std::string data;
    bool binary;
};

class OnTrackInterface {
public:
    virtual void OnRemoteTrack(Track tack, TrackAction action) = 0;
    virtual void OnData(std::shared_ptr<Data> data) = 0;
protected:
    virtual ~OnTrackInterface() = default;
};

}  // namespace stream
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_STREAM_ONTRACKINTERFACE_HPP
