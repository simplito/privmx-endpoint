/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/stream/PeerConnectionManager.hpp"
#include "privmx/endpoint/stream/StreamException.hpp"

using namespace privmx::endpoint::stream; 

PeerConnectionManager::PeerConnectionManager(
    std::function<std::shared_ptr<PeerConnection>(const std::string&)> createPeerConnection,
    std::function<void(const int64_t, const dynamic::RTCIceCandidate&)> onTrickle
) : _createPeerConnection(createPeerConnection), _onTrickle(onTrickle) {}

void PeerConnectionManager::initialize(const std::string& streamRoomId, ConnectionType connectionType, const int64_t sessionId) {
    if(_connections.has(streamRoomId)) {
        auto roomConnections = _connections.get(streamRoomId).value();
        if(roomConnections[connectionType]) {
            throw PeerConnectionAlreadyInitializedException();
        }
    }
    if(!_connections.has(streamRoomId)) {
        _connections.set(streamRoomId, std::map<ConnectionType,std::shared_ptr<JanusConnection>>());
    }
    auto pc = _createPeerConnection(streamRoomId);
    pc->observer->setOnIceCandidate([&, streamRoomId, connectionType](libwebrtc::scoped_refptr<libwebrtc::RTCIceCandidate> rtcIceCandidate) {
        auto roomConnections = _connections.get(streamRoomId).value();
        auto roomConnection = roomConnections[connectionType];
        if (rtcIceCandidate->candidate().std_string().size() > 0 && roomConnection->sessionId > -1) {
            try {
                auto iceCandidate {utils::TypedObjectFactory::createObjectFromVar<dynamic::RTCIceCandidate>(privmx::utils::Utils::parseJson(rtcIceCandidate->candidate().std_string()))};
                _onTrickle(roomConnection->sessionId, iceCandidate);
            } catch(...) {
                
            }
        }
    });
    auto roomConnections = _connections.get(streamRoomId).value();
    roomConnections[connectionType] = std::make_shared<JanusConnection>(pc ,sessionId, false);
    _connections.set(streamRoomId, roomConnections);
}

void PeerConnectionManager::updateSessionForConnection(const std::string& streamRoomId, ConnectionType connectionType, const int64_t sessionId) {
    if(!_connections.has(streamRoomId) || !_connections.get(streamRoomId).value()[connectionType]) {
        initialize(streamRoomId, connectionType, sessionId);
    }
    auto roomConnections = _connections.get(streamRoomId).value();
    roomConnections[connectionType]->sessionId = sessionId;
    _connections.set(streamRoomId, roomConnections);
}

bool PeerConnectionManager::hasConnection(const std::string& streamRoomId, ConnectionType connectionType) {
    if(_connections.has(streamRoomId)) {
        auto roomConnections = _connections.get(streamRoomId).value();
        return roomConnections[connectionType].operator bool();
    }
    return false;
}

std::shared_ptr<JanusConnection> PeerConnectionManager::getConnectionWithSession(const std::string& streamRoomId, ConnectionType connectionType) {
    if(!_connections.has(streamRoomId) || !_connections.get(streamRoomId).value()[connectionType]) {
        initialize(streamRoomId, connectionType);
    }
    return _connections.get(streamRoomId).value()[connectionType];
}
