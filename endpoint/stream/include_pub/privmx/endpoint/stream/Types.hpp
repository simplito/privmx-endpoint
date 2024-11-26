/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPI_TYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPI_TYPES_HPP_

#include <privmx/endpoint/core/Buffer.hpp>
#include <privmx/endpoint/core/Types.hpp>


namespace privmx {
namespace endpoint {
namespace stream {

template<typename T>
struct List {    
    std::vector<T> list;
};

struct VideoRoom {
    int64_t room;                   // <unique numeric ID, optional, chosen by plugin if missing>
    std::string description;        // "<pretty name of the room, optional>",
    bool pin_required;              // <true|false, whether a PIN is required to join this room>,
    bool is_private;                // <true|false, whether this room is 'private' (as in hidden) or not>,
    int64_t max_publishers;         // <how many publishers can actually publish via WebRTC at the same time>,
    int64_t bitrate;                // <bitrate cap that should be forced (via REMB) on all publishers by default>,
    int64_t bitrate_cap;            // <true|false, whether the above cap should act as a limit to dynamic bitrate changes by publishers (optional)>,
    int64_t fir_freq;               // <how often a keyframe request is sent via PLI/FIR to active publishers>,
    bool require_pvtid;             // <true|false, whether subscriptions in this room require a private_id>,
    bool require_e2ee;              // <true|false, whether end-to-end encrypted publishers are required>,
    bool dummy_publisher;           // <true|false, whether a dummy publisher exists for placeholder subscriptions>,
    bool notify_joining;            // <true|false, whether an event is sent to notify all participants if a new participant joins the room>,
    std::string audiocodec;         // "<comma separated list of allowed audio codecs>",
    std::string videocodec;         // "<comma separated list of allowed video codecs>",
    bool opus_fec;                  // <true|false, whether inband FEC must be negotiated (note: only available for Opus) (optional)>,
    bool opus_dtx;                  // <true|false, whether DTX must be negotiated (note: only available for Opus) (optional)>,
    bool record;                    // <true|false, whether the room is being recorded>,
    std::string rec_dir;            // "<if recording, the path where the .mjr files are being saved>",
    bool lock_record;               // <true|false, whether the room recording state can only be changed providing the secret>,
    int64_t num_participants;       // <count of the participants (publishers, active or not; not subscribers)>
    bool audiolevel_ext;            // <true|false, whether the ssrc-audio-level extension must be negotiated or not for new publishers>,
    bool audiolevel_event;          // <true|false, whether to emit event to other users about audiolevel>,
    int64_t audio_active_packets;   // <amount of packets with audio level for checkup (optional, only if audiolevel_event is true)>,
    int64_t audio_level_average;    // <average audio level (optional, only if audiolevel_event is true)>,
    bool videoorient_ext;           // <true|false, whether the video-orientation extension must be negotiated or not for new publishers>,
    bool playoutdelay_ext;          // <true|false, whether the playout-delay extension must be negotiated or not for new publishers>,
    bool transport_wide_cc_ext;     // <true|false, whether the transport wide cc extension must be negotiated or not for new publishers>
};

struct StreamTrackCreateMeta {
    std::optional<std::string> mid;         //"<unique mid of a stream being published>"
    std::optional<std::string> description; //"<text description of the stream (e.g., My front webcam)>"
};

struct StreamCreateMeta {
    std::optional<std::string> mid;         //"<unique mid of a stream being published>"
    std::optional<std::string> description; //"<text description of the stream (e.g., My front webcam)>"
    std::optional<bool> p2p;                // reserved for future use
    std::optional<std::vector<StreamTrackCreateMeta>> tracks;
};

struct VideoRoomStreamTrack {
    std::string type;
    std::string codec;
    std::string mid;
    int64_t mindex;
};

struct DataChannelMeta {
    std::string name;
};

struct TrackInfo: VideoRoomStreamTrack {
    std::string type;
    int64_t streamRoomId;
    int64_t streamId;
    std::optional<DataChannelMeta> meta;
    std::optional<std::string> dataTrackId;
};

struct StreamRemoteInfo {
    int64_t id;
    std::optional<std::vector<TrackInfo>> tracks;
};

struct Stream {
    int64_t streamId;
    int64_t streamRoomId;
    bool remote;
    std::optional<StreamCreateMeta> createStreamMeta;
    std::optional<StreamRemoteInfo> remoteStreamInfo;
};

struct MediaStreamTrack {
    // MediaStreamTrack - object
};

struct StreamTrackMeta {
    // Track
    std::optional<MediaStreamTrack> track;
    // DataChannel
    std::optional<DataChannelMeta> dataChannel;
};

struct StreamAndTracksSelector {
    int64_t streamRoomId;
    int64_t streamId;
    std::optional<std::vector<std::string>> tracks;
};

}  // namespace stream
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPI_TYPES_HPP_
