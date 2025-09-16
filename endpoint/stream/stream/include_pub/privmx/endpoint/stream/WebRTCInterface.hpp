/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STREAM_WEBRTCINTERFACE_HPP_
#define _PRIVMXLIB_ENDPOINT_STREAM_WEBRTCINTERFACE_HPP_

#include <string>
#include <vector>

#include "privmx/endpoint/core/Buffer.hpp"

namespace privmx {
namespace endpoint {
namespace stream {

enum KeyType 
{
    LOCAL,
    REMOTE
};

struct Key
{
    std::string keyId;
    core::Buffer key;
    KeyType type;
};

class WebRTCInterface
{
public:
    virtual std::string createOfferAndSetLocalDescription() = 0;
    // virtual std::string createAnswerAndSetDescriptions(const std::string& sdp, const std::string& type) = 0;
    virtual std::string createAnswerAndSetDescriptions(const std::string& streamRoomId, const int64_t sessionId, const std::string& sdp, const std::string& type) = 0;
    virtual void setAnswerAndSetRemoteDescription(const std::string& sdp, const std::string& type) = 0;
    virtual void close() = 0;
    virtual void updateKeys(const std::vector<Key>& keys) = 0;

protected:
    virtual ~WebRTCInterface() = default;
};

} // namespace stream
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_WEBRTCINTERFACE_HPP_
