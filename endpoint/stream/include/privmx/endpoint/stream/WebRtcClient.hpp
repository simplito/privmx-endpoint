/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STREAM_WEBRTC_CLIENT_HPP_
#define _PRIVMXLIB_ENDPOINT_STREAM_WEBRTC_CLIENT_HPP_

#include <string>
#include <memory>


namespace privmx {
namespace endpoint {
namespace stream {

class WebRtcClient {
public:
    std::string provideSession(); // unused
    // std::shared_ptr<AppServerChannel> getAppServerChannel();
    // std::shared_ptr<SignalingApi> getSignalingApi(); // unused
    void setEncKey(const std::string& key, const std::string& iv);
    // void addRemoteStreamListener(std::function<void(const VideoStream& type)> listener)
    // RTCPeerConnection createPeerConnectionWithLocalStream(const MediaStream& stream);
    void createDataChannel(const std::string& name);
    void sendToChannel(const std::string& name, const std::string& message);

};

} // stream
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_WEBRTC_CLIENT_HPP_
