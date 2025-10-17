#include <future>

#include "privmx/endpoint/stream/WebRTCImpl.hpp"
#include "privmx/endpoint/stream/StreamException.hpp"
#include <privmx/utils/Debug.hpp>

using namespace privmx::endpoint::stream;

WebRTCImpl::WebRTCImpl(
    libwebrtc::scoped_refptr<libwebrtc::RTCPeerConnectionFactory> peerConnectionFactory,
    libwebrtc::scoped_refptr<libwebrtc::RTCMediaConstraints> constraints,
    libwebrtc::RTCConfiguration configuration,
    std::function<void(const int64_t, const dynamic::RTCIceCandidate&)> onTrickle,
    privmx::webrtc::FrameCryptorOptions frameCryptorOptions
) :
    _peerConnectionFactory(peerConnectionFactory),
    _constraints(constraints),
    _configuration(configuration),
    _frameCryptorOptions(frameCryptorOptions)
{
    _peerConnectionManager = std::make_shared<PeerConnectionManager>(
        std::bind(&WebRTCImpl::createPeerConnection, this, std::placeholders::_1),
        onTrickle
    );
}

WebRTCImpl::~WebRTCImpl() {}

std::string WebRTCImpl::createOfferAndSetLocalDescription(const std::string& streamRoomId) {
    auto peerConnection = _peerConnectionManager->getConnectionWithSession(streamRoomId, ConnectionType::Publisher)->peerConnection;
    std::promise<std::string> t_spd = std::promise<std::string>();
    peerConnection->pc->CreateOffer(
        [&](const libwebrtc::string sdp, [[maybe_unused]] const libwebrtc::string type) {
            t_spd.set_value(sdp.std_string());
        },
        [&](const char* error) {
            throw stream::WebRTCException("SdpCreateFailure" + std::string(error));
        }, 
        _constraints
    );

    std::string sdp = t_spd.get_future().get();
    peerConnection->pc->SetLocalDescription(
        sdp, 
        "offer", 
        []() {}, 
        [](const char* error) {
            throw stream::WebRTCException("OnSetSdpFailure" + std::string(error));
        }
    );
    return sdp;
}
std::string WebRTCImpl::createAnswerAndSetDescriptions(const std::string& streamRoomId, const std::string& sdp, const std::string& type) {
    auto peerConnection = _peerConnectionManager->getConnectionWithSession(streamRoomId, ConnectionType::Subscriber)->peerConnection;
    // Set remote description
    std::promise<bool> tmp = std::promise<bool>();
    peerConnection->pc->SetRemoteDescription(
        sdp, 
        type,
        [&]() {tmp.set_value(true);}, 
        [&](const char* error) {
            tmp.set_value(false);
            std::cout << "OnSetSdpFailure: " << std::string(error) << std::endl;
            throw stream::WebRTCException("OnSetSdpFailure" + std::string(error));
        }
    );
    if (!tmp.get_future().get()) {
        throw stream::WebRTCException("SetRemoteDescriptionFailed");
    }
    // Create answer
    std::promise<std::string> answer_spd = std::promise<std::string>();
    peerConnection->pc->CreateAnswer(
        [&](const libwebrtc::string sdp, [[maybe_unused]] const libwebrtc::string type) {
            answer_spd.set_value(sdp.std_string());
        },
        [&](const char* error) {
            throw stream::WebRTCException("SdpCreateFailure" + std::string(error));
        }, 
        _constraints
    );
    std::string result_sdp = answer_spd.get_future().get();
    peerConnection->pc->SetLocalDescription(
        result_sdp, 
        "answer",
        [&]() {}, 
        [&](const char* error) {
            throw stream::WebRTCException("OnSetSdpFailure" + std::string(error));
        }
    );
    return result_sdp;
}

void WebRTCImpl::updateSessionId(const std::string& streamRoomId, const int64_t sessionId, const std::string& connectionType) {
    if(connectionType == "subscriber") {
        _peerConnectionManager->updateSessionForConnection(streamRoomId, ConnectionType::Subscriber, sessionId);
    } else if(connectionType == "publisher") {
        _peerConnectionManager->updateSessionForConnection(streamRoomId, ConnectionType::Publisher, sessionId);
    }
}

void WebRTCImpl::setAnswerAndSetRemoteDescription(const std::string& streamRoomId, const std::string& sdp, const std::string& type) {
    auto peerConnection = _peerConnectionManager->getConnectionWithSession(streamRoomId, ConnectionType::Publisher)->peerConnection;
    peerConnection->pc->SetRemoteDescription(
        sdp, 
        type,
        [&]() {}, 
        [&](const char* error) {
            throw stream::WebRTCException("OnSetSdpFailure" + std::string(error));
        }
    );
}

void WebRTCImpl::close(const std::string& streamRoomId) {
    PRIVMX_DEBUG("STREAMS", "WebRTC_IMPL", "WebRTCImpl::close()");
    auto peerConnection_1 = _peerConnectionManager->getConnectionWithSession(streamRoomId, ConnectionType::Publisher)->peerConnection;
    peerConnection_1->audioTracks.clear();
    peerConnection_1->videoTracks.clear();
    peerConnection_1->pc->Close();
    auto peerConnection_2 = _peerConnectionManager->getConnectionWithSession(streamRoomId, ConnectionType::Subscriber)->peerConnection;
    peerConnection_2->audioTracks.clear();
    peerConnection_2->videoTracks.clear();
    peerConnection_2->pc->Close();
}

void WebRTCImpl::updateKeys(const std::string& streamRoomId, const std::vector<Key>& keys) {
    {
    auto peerConnection_p = _peerConnectionManager->getConnectionWithSession(streamRoomId, ConnectionType::Publisher)->peerConnection;
    auto peerConnection_s = _peerConnectionManager->getConnectionWithSession(streamRoomId, ConnectionType::Subscriber)->peerConnection;
    std::string keysIds;
    for(auto k: keys) keysIds += (k.keyId + ", ");
    std::cout << "RecivedKyesIds: " << keysIds << std::endl;
    PRIVMX_DEBUG("STREAMS", "WebRTC", "updateKeys createWebRtcKeyStore");
    {
        std::unique_lock<std::shared_mutex> lock1(peerConnection_p->trackMutex);
        std::unique_lock<std::shared_mutex> lock2(peerConnection_s->trackMutex);
        peerConnection_s->keys = createWebRtcKeyStore(keys);
        peerConnection_p->keys = createWebRtcKeyStore(keys);
        PRIVMX_DEBUG("STREAMS", "WebRTC", "updateKeys _peerConnectionObserver->UpdateCurrentKeys");
        // update input data keys 
        peerConnection_p->observer->UpdateCurrentKeys(peerConnection_p->keys);
        peerConnection_s->observer->UpdateCurrentKeys(peerConnection_s->keys);
    }
    PRIVMX_DEBUG("STREAMS", "WebRTC", "updateKeys for_each->_audioTracks");
    {
        std::unique_lock<std::shared_mutex> lock1(peerConnection_p->trackMutex);
        std::unique_lock<std::shared_mutex> lock2(peerConnection_s->trackMutex);
        // update out data keys
        std::for_each(
            peerConnection_p->audioTracks.begin(),
            peerConnection_p->audioTracks.end(), 
            [&](const auto& p) {p.second.frameCryptor->setKeyStore(peerConnection_p->keys);}
        );
        std::for_each(
            peerConnection_s->audioTracks.begin(),
            peerConnection_s->audioTracks.end(), 
            [&](const auto& p) {p.second.frameCryptor->setKeyStore(peerConnection_s->keys);}
        );
        PRIVMX_DEBUG("STREAMS", "WebRTC", "updateKeys for_each->_videoTracks");
        std::for_each(
            peerConnection_p->videoTracks.begin(),
            peerConnection_p->videoTracks.end(), 
            [&](const auto& p) {p.second.frameCryptor->setKeyStore(peerConnection_p->keys);}
        );
        std::for_each(
            peerConnection_s->videoTracks.begin(),
            peerConnection_s->videoTracks.end(), 
            [&](const auto& p) {p.second.frameCryptor->setKeyStore(peerConnection_s->keys);}
        );
    }
    }
}

void WebRTCImpl::AddAudioTrack(const std::string& streamRoomId, libwebrtc::scoped_refptr<libwebrtc::RTCAudioTrack> audioTrack, int64_t id) {
    auto connection = _peerConnectionManager->getConnectionWithSession(streamRoomId, ConnectionType::Publisher);
    auto sender = connection->peerConnection->pc->AddTrack(audioTrack, libwebrtc::vector<libwebrtc::string>{std::vector<libwebrtc::string>{std::to_string(id)}});
    std::shared_ptr<privmx::webrtc::FrameCryptor> frameCryptor;
    {
        std::shared_lock<std::shared_mutex> lock(connection->peerConnection->trackMutex);
        frameCryptor = privmx::webrtc::FrameCryptorFactory::frameCryptorFromRtpSender(
            _peerConnectionFactory,
            sender, 
            connection->peerConnection->keys,
            _frameCryptorOptions
        );
    }
    {
        std::unique_lock<std::shared_mutex> lock(connection->peerConnection->trackMutex);
        connection->peerConnection->audioTracks.insert(std::make_pair(
            id, 
            AudioTrackInfo{
                .track=audioTrack, 
                .sender=sender, 
                .frameCryptor=frameCryptor
            }
        ));
    }
}

void WebRTCImpl::AddVideoTrack(const std::string& streamRoomId, libwebrtc::scoped_refptr<libwebrtc::RTCVideoTrack> videoTrack, int64_t id) {
    auto connection = _peerConnectionManager->getConnectionWithSession(streamRoomId, ConnectionType::Publisher);
    auto sender = connection->peerConnection->pc->AddTrack(videoTrack, libwebrtc::vector<libwebrtc::string>{std::vector<libwebrtc::string>{std::to_string(id)}});
    std::shared_ptr<privmx::webrtc::FrameCryptor> frameCryptor;
    {
        std::shared_lock<std::shared_mutex> lock(connection->peerConnection->trackMutex);
        frameCryptor = privmx::webrtc::FrameCryptorFactory::frameCryptorFromRtpSender(
            _peerConnectionFactory,
            sender, 
            connection->peerConnection->keys,
            _frameCryptorOptions
        );
    }
    {
        std::unique_lock<std::shared_mutex> lock(connection->peerConnection->trackMutex);
        connection->peerConnection->videoTracks.insert(std::make_pair(
            id, 
            VideoTrackInfo{
                .track=videoTrack, 
                .sender=sender, 
                .frameCryptor=frameCryptor
            }
        ));
    }
    
}

void WebRTCImpl::RemoveAudioTrack(const std::string& streamRoomId, int64_t id) {
    auto connection = _peerConnectionManager->getConnectionWithSession(streamRoomId, ConnectionType::Publisher);
    std::unique_lock<std::shared_mutex> lock(connection->peerConnection->trackMutex);
    auto it = connection->peerConnection->audioTracks.find(id);
    if(it != connection->peerConnection->audioTracks.end()) {
        // _mediaStream->RemoveTrack(it->second.track);
        connection->peerConnection->pc->RemoveTrack(it->second.sender);
        connection->peerConnection->audioTracks.erase(it);
    } else {
        throw IncorrectTrackIdException();
    }
}

void WebRTCImpl::RemoveVideoTrack(const std::string& streamRoomId, int64_t id) {
    auto connection = _peerConnectionManager->getConnectionWithSession(streamRoomId, ConnectionType::Publisher);
    std::unique_lock<std::shared_mutex> lock(connection->peerConnection->trackMutex);
    auto it = connection->peerConnection->audioTracks.find(id);
    if(it != connection->peerConnection->audioTracks.end()) {
        // _mediaStream->RemoveTrack(it->second.track);
        connection->peerConnection->pc->RemoveTrack(it->second.sender);
        connection->peerConnection->audioTracks.erase(it);
    } else {
        throw IncorrectTrackIdException();
    }
}

std::shared_ptr<privmx::webrtc::KeyStore> WebRTCImpl::createWebRtcKeyStore(const std::vector<privmx::endpoint::stream::Key>& keys) {
    std::vector<privmx::webrtc::Key> webRtcKeys;
    for(size_t i = 0; i < keys.size(); i++) {
        webRtcKeys.push_back(
            privmx::webrtc::Key{.
                keyId=keys[i].keyId, 
                .key=keys[i].key.stdString(), 
                .type=keys[i].type == privmx::endpoint::stream::KeyType::REMOTE ? privmx::webrtc::KeyType::REMOTE : privmx::webrtc::KeyType::LOCAL
            }
        );
    }
    return privmx::webrtc::KeyStore::Create(webRtcKeys);
}

std::shared_ptr<PeerConnection> WebRTCImpl::createPeerConnection(const std::string& streamRoomId) {
    auto peerConnection = std::make_shared<PeerConnection>();
    auto tmp = _peerConnectionFactory->Create(_configuration, _constraints);
    peerConnection->pc = tmp;
    peerConnection->observer = std::make_shared<PmxPeerConnectionObserver>(_peerConnectionFactory, streamRoomId, privmx::webrtc::KeyStore::Create(std::vector<privmx::webrtc::Key>()), _frameCryptorOptions);
    peerConnection->pc->RegisterRTCPeerConnectionObserver(peerConnection->observer.get());
    return peerConnection;
}

void WebRTCImpl::setOnFrame(const std::string& streamRoomId, std::function<void(int64_t, int64_t, std::shared_ptr<Frame>, const std::string&)> OnFrame) {
    auto connection = _peerConnectionManager->getConnectionWithSession(streamRoomId, ConnectionType::Subscriber);
    connection->peerConnection->observer->setOnFrame(OnFrame);

}