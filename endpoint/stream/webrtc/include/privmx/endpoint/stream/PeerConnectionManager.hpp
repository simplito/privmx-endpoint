/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_WEBRTC_PEER_CONNECTIN_MANAGER_HPP_
#define _PRIVMXLIB_ENDPOINT_WEBRTC_PEER_CONNECTIN_MANAGER_HPP_

#include <string>
#include <memory>
#include <libwebrtc.h>
#include <rtc_peerconnection.h>
#include "privmx/endpoint/stream/webrtc/Types.hpp"
#include "privmx/endpoint/stream/DynamicTypes.hpp"
#include "privmx/endpoint/stream/PmxPeerConnectionObserver.hpp"
#include <privmx/utils/ThreadSaveMap.hpp>

namespace privmx {
namespace endpoint {
namespace stream {

enum ConnectionType {
    Subscriber = 0,
    Publisher = 1
};

struct AudioTrackInfo {
    libwebrtc::scoped_refptr<libwebrtc::RTCAudioTrack> track;
    libwebrtc::scoped_refptr<libwebrtc::RTCRtpSender> sender;
    std::shared_ptr<privmx::webrtc::FrameCryptor> frameCryptor;
};

struct VideoTrackInfo {
    libwebrtc::scoped_refptr<libwebrtc::RTCVideoTrack> track;
    libwebrtc::scoped_refptr<libwebrtc::RTCRtpSender> sender;
    std::shared_ptr<privmx::webrtc::FrameCryptor> frameCryptor;
};

struct PeerConnection {
    libwebrtc::scoped_refptr<libwebrtc::RTCPeerConnection> pc;
    std::shared_ptr<PmxPeerConnectionObserver> observer;
    std::map<std::string, AudioTrackInfo> audioTracks;
    std::map<std::string, VideoTrackInfo> videoTracks;
    std::shared_mutex trackMutex;
    std::shared_ptr<privmx::webrtc::KeyStore> keys;
};

struct JanusConnection {
    JanusConnection(std::shared_ptr<PeerConnection> peerConnection_, int64_t sessionId_, bool hasSubscriptions_) :
        peerConnection(peerConnection_), sessionId(sessionId_), hasSubscriptions(hasSubscriptions_) {}
    std::shared_ptr<PeerConnection> peerConnection;
    int64_t sessionId;
    bool hasSubscriptions;
};
class PeerConnectionManager {
public:
    PeerConnectionManager(
        std::function<std::shared_ptr<PeerConnection>(const std::string&)> createPeerConnection,
        std::function<void(const int64_t, const dynamic::RTCIceCandidate&)> onTrickle
    );
    void initialize(const std::string& streamRoomId, ConnectionType connectionType, const int64_t sessionId = -1);
    void updateSessionForConnection(const std::string& streamRoomId, ConnectionType connectionType, const int64_t sessionId);
    bool hasConnection(const std::string& streamRoomId, ConnectionType connectionType);
    std::shared_ptr<JanusConnection> getConnectionWithSession(const std::string& streamRoomId, ConnectionType connectionType);
private:
    std::function<std::shared_ptr<PeerConnection>(const std::string&)> _createPeerConnection;
    std::function<void(const int64_t, const dynamic::RTCIceCandidate&)> _onTrickle;
    privmx::utils::ThreadSaveMap<std::string, std::map<ConnectionType,std::shared_ptr<JanusConnection>>> _connections;
};

} // stream
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_WEBRTC_PEER_CONNECTIN_MANAGER_HPP_
