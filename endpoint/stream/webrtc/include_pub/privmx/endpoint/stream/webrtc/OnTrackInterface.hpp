#ifndef _PRIVMXLIB_ENDPOINT_STREAM_ONTRACKINTERFACE_HPP
#define _PRIVMXLIB_ENDPOINT_STREAM_ONTRACKINTERFACE_HPP

#include <functional>
#include <memory>
#include <optional>
#include <privmx/endpoint/stream/Types.hpp>
#include <string>
#include <vector>

namespace privmx {
namespace endpoint {
namespace stream {

/**
 * Changes which happen to a remote track.
 */
enum TrackAction {
    /**
     * the track is gone, because its publisher removed it or the Stream stopped
     */
    REMOVED,

    /**
     * the track arrived and starts delivering its content
     */
    ADDED
};

/**
 * Kinds of content which a remote track delivers.
 */
enum DataType {
    /**
     * video frames
     */
    VIDEO,

    /**
     * audio samples
     */
    AUDIO,

    /**
     * binary messages sent over a data track
     */
    PLAIN
};

/**
 * Describes a remote track of a Stream you subscribe to.
 */
struct Track {
    /**
     * kind of content which the track delivers
     */
    DataType kind;

    /**
     * IDs of the remote Streams which the track belongs to. The data tracks carry no Stream IDs.
     */
    std::vector<std::string> streamIds;

    /**
     * ID of the track
     */
    std::string trackId;

    /**
     * determines whether the track is muted locally
     */
    bool muted;

    /**
     * mutes and unmutes the track for the local user only. It changes nothing for the other participants and the
     * data tracks ignore it.
     */
    std::function<void(bool)> updateMute;
};

/**
 * Holds the content which a remote track delivers.
 *
 * Read `type` to learn what arrived, then cast the struct to `VideoData`, `AudioData`, or `PlainData`.
 */
struct Data {
    /**
     * //doc-gen:ignore
     */
    Data(DataType _type, const std::vector<std::string>& _streamIds, const std::string& _track)
        : type(_type), streamIds(_streamIds), track(_track) {}

    /**
     * //doc-gen:ignore
     */
    virtual ~Data() = default;

    /**
     * kind of the delivered content, which tells you the type to cast this struct to
     */
    DataType type;

    /**
     * IDs of the remote Streams which the content comes from
     */
    const std::vector<std::string> streamIds;

    /**
     * ID of the track which delivered the content
     */
    const std::string track;
};

/**
 * Holds a single video frame.
 */
class Frame {
public:
    /**
     * Converts the frame into an RGBA image.
     *
     * @param dst_argb buffer to write the image to
     * @param dst_stride_argb number of bytes between the beginnings of two consecutive rows of the buffer
     * @param dest_width width of the resulting image in pixels
     * @param dest_height height of the resulting image in pixels
     *
     * @return 0 on success
     */
    virtual int ConvertToRGBA(uint8_t* dst_argb, int dst_stride_argb, int dest_width, int dest_height) = 0;
};

/**
 * Holds a video frame delivered by a remote track.
 */
struct VideoData : public Data {
    /**
     * //doc-gen:ignore
     */
    VideoData(
        const std::vector<std::string>& _streamIds,
        const std::string& _track,
        const int64_t _w,
        const int64_t _h,
        std::shared_ptr<Frame> _frameData
    )
        : Data(DataType::VIDEO, _streamIds, _track), w(_w), h(_h), frameData(_frameData) {}

    /**
     * width of the frame in pixels
     */
    const int64_t w;

    /**
     * height of the frame in pixels
     */
    const int64_t h;

    /**
     * the frame itself, which you convert to an image with `Frame::ConvertToRGBA`
     */
    std::shared_ptr<Frame> frameData;
};

/**
 * Holds a portion of audio delivered by a remote track.
 */
struct AudioData : public Data {
    /**
     * //doc-gen:ignore
     */
    AudioData(
        const std::vector<std::string>& _streamIds,
        const std::string& _track,
        const void* _audio_data,
        int _bits_per_sample,
        int _sample_rate,
        size_t _number_of_channels,
        size_t _number_of_frames
    )
        : Data(DataType::AUDIO, _streamIds, _track), audio_data(_audio_data), bits_per_sample(_bits_per_sample),
          sample_rate(_sample_rate), number_of_channels(_number_of_channels), number_of_frames(_number_of_frames) {}

    /**
     * raw samples, which the sender owns. They live as long as the `OnData` call, so copy them to keep them.
     */
    const void* audio_data;

    /**
     * number of bits which every sample takes
     */
    int bits_per_sample;

    /**
     * number of samples per second
     */
    int sample_rate;

    /**
     * number of channels which the samples interleave
     */
    size_t number_of_channels;

    /**
     * number of frames in this portion, where one frame holds one sample for every channel
     */
    size_t number_of_frames;
};

/**
 * Holds a decrypted message delivered by a remote data track.
 */
struct PlainData : public Data {
    /**
     * //doc-gen:ignore
     */
    PlainData(
        const std::vector<std::string>& _streamIds,
        const std::string& _track,
        const core::Buffer& _data,
        const uint64_t& _seq,
        bool _binary,
        const uint64_t& _statusCode
    )
        : Data(DataType::PLAIN, _streamIds, _track), data(_data), seq(_seq), binary(_binary), statusCode(_statusCode) {}

    /**
     * content of the message
     */
    core::Buffer data;

    /**
     * sequence number of the message, which grows with every message the sender sends
     */
    uint64_t seq;

    /**
     * determines whether the sender sent the message as binary data rather than as text
     */
    bool binary;

    /**
     * status code of decryption of the message. A value other than 0 means that the message failed to decrypt or
     * that its data integrity has been violated.
     */
    uint64_t statusCode;
};

/**
 * Interface which delivers the content of the Streams you subscribe to.
 *
 * Register your implementation with `StreamApi::addRemoteStreamListener`, either for one remote Stream or for
 * every Stream in the Stream Room. The library calls these methods on its own threads, so keep them short and
 * hand the heavy work over to a thread of your own.
 */
class OnTrackInterface {
public:
    /**
     * Reports that a remote track arrived or that it is gone.
     *
     * @param tack the track which the change concerns
     * @param action change which happened to the track
     */
    virtual void OnRemoteTrack(Track tack, TrackAction action) = 0;

    /**
     * Delivers the content of a remote track.
     *
     * This method runs for every video frame, every portion of audio, and every message of a data track, so it
     * runs often.
     *
     * @param data delivered content, which you cast to `VideoData`, `AudioData`, or `PlainData` after reading its
     * `type`
     */
    virtual void OnData(std::shared_ptr<Data> data) = 0;

protected:
    /**
     * //doc-gen:ignore
     */
    virtual ~OnTrackInterface() = default;
};

} // namespace stream
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_ONTRACKINTERFACE_HPP
