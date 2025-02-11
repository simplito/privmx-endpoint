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
#include <functional>

namespace privmx {
namespace endpoint {
namespace stream {

class Frame {
public:
    virtual int ConvertToRGBA(uint8_t* dst_argb, int dst_stride_argb, int dest_width, int dest_height) = 0;
};

struct streamJoinSettings {
    std::optional<std::function<void(int64_t, int64_t, std::shared_ptr<Frame>, const std::string&)>> OnFrame;

};

enum DeviceType {
    Audio,
    Video,
    Desktop
};

struct StreamRoom {
    std::string contextId;
    std::string streamRoomId;
    int64_t createDate;
    std::string creator;
    int64_t lastModificationDate;
    std::string lastModifier;
    std::vector<std::string> users;
    std::vector<std::string> managers;
    int64_t version;
    core::Buffer publicMeta;
    core::Buffer privateMeta;
    core::ContainerPolicy policy;
    int64_t statusCode;
};

struct Stream {
    int64_t streamId;
    std::string userId;
};

}  // namespace stream
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPI_TYPES_HPP_
