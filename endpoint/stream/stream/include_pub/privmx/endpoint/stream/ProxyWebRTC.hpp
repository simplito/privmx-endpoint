/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STREAM_PROXYWEBRTC_HPP_
#define _PRIVMXLIB_ENDPOINT_STREAM_PROXYWEBRTC_HPP_

#include <string>
#include <vector>

#include "privmx/endpoint/core/Buffer.hpp"
#include "privmx/endpoint/stream/Types.hpp"
#include "privmx/endpoint/stream/WebRTCInterface.hpp"
#include "privmx/endpoint/stream/cinterface/streamlow.h"

namespace privmx {
namespace endpoint {
namespace stream {

class ProxyWebRTC : public WebRTCInterface
{
public:
    ProxyWebRTC(
        privmx_endpoint_stream_WebRTCInterface webRTCInterface
    );
    ~ProxyWebRTC() override = default;
    std::string createOfferAndSetLocalDescription(const std::string& streamRoomId) override;
    std::string createAnswerAndSetDescriptions(const std::string& streamRoomId, const std::string& sdp, const std::string& type) override;
    void setAnswerAndSetRemoteDescription(const std::string& streamRoomId, const std::string& sdp, const std::string& type) override;
    void updateSessionId(const std::string& streamRoomId, const int64_t sessionId, const std::string& connectionType) override;
    void close(const std::string& streamRoomId) override;
    void updateKeys(const std::string& streamRoomId, const std::vector<Key>& keys) override;

private:
    std::shared_ptr<privmx_endpoint_stream_Key> mapKeys(const std::vector<Key>& keys);
    privmx_endpoint_stream_KeyType mapKeyType(KeyType type);

    privmx_endpoint_stream_WebRTCInterface _webRTCInterface;
};

} // namespace stream
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_PROXYWEBRTC_HPP_
