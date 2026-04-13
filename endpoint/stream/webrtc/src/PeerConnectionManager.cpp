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
#include "privmx/endpoint/core/Buffer.hpp"
#include <privmx/utils/Logger.hpp>

using namespace privmx::endpoint::stream; 

void PeerConnection::sendData(const std::string& data) {
    if(!dataChannel) {
        return;
    }
    const auto messageSeq = messagesSeq.fetch_add(1);
    LOG_TRACE("DataChannel::Send seq: ", messageSeq, "| data:", data);
    auto encryptedData = messageEncryptor->encryptMessage(privmx::endpoint::core::Buffer::from(data), messageSeq).stdString();
    dataChannel->channel->Send(
        reinterpret_cast<const uint8_t*>(encryptedData.c_str()), encryptedData.size(), true
    );
}

PeerConnectionManager::PeerConnectionManager(
    std::function<std::shared_ptr<PeerConnection>(const std::string&)> createPeerConnection,
    std::function<void(const int64_t, const std::string&)> onTrickle
) : _createPeerConnection(createPeerConnection), _onTrickle(onTrickle) {}

void PeerConnectionManager::initialize(const std::string& streamRoomId, ConnectionType connectionType, const int64_t sessionId) {
    LOG_DEBUG("PeerConnectionManager::initialize")
    if(_connections.has(streamRoomId)) {
        auto roomConnections = _connections.get(streamRoomId).value();
        if(roomConnections[connectionType]) {
            return;
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
                auto iceCandidate {rtcIceCandidate->candidate().std_string()};
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
        LOG_TRACE("PeerConnectionManager::getConnectionWithSession ", "streamRoom - require initialize")
        initialize(streamRoomId, connectionType);
    }
    LOG_TRACE("PeerConnectionManager::getConnectionWithSession ", "get form map")
    return _connections.get(streamRoomId).value()[connectionType];
}

void PeerConnectionManager::closeConnection(const std::string& streamRoomId, ConnectionType connectionType) {
    if(!_connections.has(streamRoomId) || !_connections.get(streamRoomId).value()[connectionType]) {
        return;
    }
    auto jc = _connections.get(streamRoomId).value()[connectionType];
    jc->peerConnection->audioTracks.clear();
    jc->peerConnection->videoTracks.clear();
    jc->peerConnection->pc->Close();
    jc->peerConnection->observer.reset();
    _connections.get(streamRoomId).value().erase(connectionType);
}

void PeerConnectionManager::closeSession(const std::string& streamRoomId) {
    _connections.erase(streamRoomId);
}
