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

namespace privmx {
namespace endpoint {
namespace stream {

struct StreamSettings {
    Settings settings;
    std::optional<std::function<void(const std::string&)>> OnVideo;
    std::optional<std::function<void(int64_t, int64_t, std::shared_ptr<Frame>, const std::string&)>> OnFrame;
    std::optional<std::function<void(const std::string&)>> OnVideoRemove;
    bool dropCorruptedFrames = true;
};




}  // namespace stream
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPI_WEBRTC_TYPES_HPP_
