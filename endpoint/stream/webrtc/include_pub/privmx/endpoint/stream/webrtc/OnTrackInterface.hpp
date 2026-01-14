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
    std::string id;
    bool muted;
};
// struct Stream {
//     std::vector<Track> tracks;
//     std::string label;
//     std::string id;
// };
struct TrackEvent {
    std::string id;
    std::optional<Track> track;
    Stream stream;
};
struct Data {
    Data(DataType _type, const std::string _streamId, const std::string _track) 
        : type(_type), streamId(_streamId), track(_track) {}
    virtual ~Data() = default;
    DataType type;
    const std::string streamId;
    const std::string track;
};
struct VideoData : public Data {
    VideoData(DataType _type, const std::string _streamId, const std::string _track, const int64_t _w,  const int64_t _h, std::shared_ptr<Frame> _frameData ) 
        : Data(_type, _streamId, _track), w(_w), h(_h), frameData(_frameData) {}
    const int64_t w; 
    const int64_t h; 
    std::shared_ptr<Frame> frameData;
};
struct AudioData : public Data {
    AudioData(DataType _type, const std::string _streamId, const std::string _track, const void* _audio_data, int _bits_per_sample, int _sample_rate, size_t _number_of_channels, size_t _number_of_frames) 
        : Data(_type, _streamId, _track), audio_data(_audio_data), bits_per_sample(_bits_per_sample), sample_rate(_sample_rate), number_of_channels(_number_of_channels), number_of_frames(_number_of_frames) {}
    const void* audio_data; 
    int bits_per_sample;
    int sample_rate;
    size_t number_of_channels; 
    size_t number_of_frames;
};
struct PlainData : public Data {
    
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
