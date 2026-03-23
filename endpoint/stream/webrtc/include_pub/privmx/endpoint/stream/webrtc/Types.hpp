/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPI_WEBRTC_TYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPI_WEBRTC_TYPES_HPP_

#include "privmx/endpoint/stream/Types.hpp"
#include "privmx/endpoint/stream/webrtc/OnTrackInterface.hpp"

namespace privmx {
namespace endpoint {
namespace stream {

enum DeviceType {
    Audio = 0,
    Video = 1,
    Desktop_Screen = 2,
    Desktop_Window = 3,
    Plain = 4
};

enum DesktopType {
    Screen = 0,
    Window = 1
};

struct MediaDevice {
    std::string name;
    std::string id;
    DeviceType type;
};

struct AudioDevice : public MediaDevice {};
struct VideoDevice : public MediaDevice {};
struct DesktopDevice : public MediaDevice {
    std::vector<unsigned char> thumbnail;
    
};

struct MediaTrackConstrains {
    // Video only
    size_t idealWidth = 1280;
    size_t idealHeight = 720;
    // Video/Desktop
    size_t idealFps = 15;
};

struct MediaTrack {
    std::function<void(bool)> setEnabled;
};



}  // namespace stream
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPI_WEBRTC_TYPES_HPP_
