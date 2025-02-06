/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STREAM_WEBRTC_HPP_
#define _PRIVMXLIB_ENDPOINT_STREAM_WEBRTC_HPP_

#include <string>
#include <vector>

#include "privmx/endpoint/stream/WebRTCInterface.hpp"

namespace privmx {
namespace endpoint {
namespace stream {

class WebRTC : public WebRTCInterface
{
public:
    WebRTC(libwebrtc::scoped_refptr<libwebrtc::RTCPeerConnection> peerConnection, std::shared_ptr<PmxPeerConnectionObserver> peerConnectionObserver);
    std::string createOfferAndSetLocalDescription() override;
    std::string createAnswerAndSetDescriptions(const std::string& sdp, const std::string& type) override;
    void setAnswerAndSetRemoteDescription(const std::string& sdp, const std::string& type) override;
    void close() override;
    void updateKeys(const std::vector<Key>& keys) override;

private:
    libwebrtc::scoped_refptr<libwebrtc::RTCPeerConnection> _peerConnection;
    std::shared_ptr<PmxPeerConnectionObserver> _peerConnectionObserver;
};

} // namespace stream
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_WEBRTC_HPP_
