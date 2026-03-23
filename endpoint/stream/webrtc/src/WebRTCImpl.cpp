#include "privmx/endpoint/stream/WebRTCImpl.hpp"
#include "privmx/endpoint/stream/StreamException.hpp"
#include "privmx/endpoint/stream/PeerConnectionManager.hpp"
#include "privmx/endpoint/stream/DataChannelImpl.hpp"
#include <future>
#include <privmx/utils/Logger.hpp>

using namespace privmx::endpoint::stream;

WebRTCImpl::WebRTCImpl(
    libwebrtc::scoped_refptr<libwebrtc::RTCPeerConnectionFactory> peerConnectionFactory,
    libwebrtc::scoped_refptr<libwebrtc::RTCMediaConstraints> constraints,
    libwebrtc::RTCConfiguration configuration,
    std::function<void(const int64_t, const std::string&)> onTrickle,
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
            throw stream::WebRTCException("SdpCreateFailure " + std::string(error));
        }, 
        _constraints
    );

    std::string sdp = t_spd.get_future().get();
    peerConnection->pc->SetLocalDescription(
        sdp, 
        "offer", 
        []() {}, 
        [](const char* error) {
            throw stream::WebRTCException("OnSetSdpFailure " + std::string(error));
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
            throw stream::WebRTCException("OnSetSdpFailure " + std::string(error));
        }
    );
    if (tmp.get_future().wait_for(std::chrono::seconds(5)) == std::future_status::timeout) {
        throw stream::WebRTCException("SetRemoteDescriptionFailed");
    }
    // Create answer
    std::promise<std::string> answer_spd = std::promise<std::string>();
    _tmp = peerConnection->pc->CreateDataChannel("JanusDataChannel", new libwebrtc::RTCDataChannelInit());
    peerConnection->pc->CreateAnswer(
        [&](const libwebrtc::string sdp, [[maybe_unused]] const libwebrtc::string type) {
            answer_spd.set_value(sdp.std_string());
        },
        [&](const char* error) {
            throw stream::WebRTCException("SdpCreateFailure " + std::string(error));
        }, 
        _constraints
    );
    std::string result_sdp = answer_spd.get_future().get();
    peerConnection->pc->SetLocalDescription(
        result_sdp, 
        "answer",
        [&]() {}, 
        [&](const char* error) {
            throw stream::WebRTCException("OnSetSdpFailure " + std::string(error));
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
            throw stream::WebRTCException("OnSetSdpFailure " + std::string(error));
        }
    );
}

void WebRTCImpl::close(const std::string& streamRoomId) {
    LOG_DEBUG("STREAMS", "WebRTC_IMPL", "WebRTCImpl::close()");
    _peerConnectionManager->closeConnection(streamRoomId, ConnectionType::Publisher);
    _peerConnectionManager->closeConnection(streamRoomId, ConnectionType::Subscriber);
    _peerConnectionManager->closeSession(streamRoomId);
}

void WebRTCImpl::updateKeys(const std::string& streamRoomId, const std::vector<Key>& keys) {
    auto peerConnection_p = _peerConnectionManager->getConnectionWithSession(streamRoomId, ConnectionType::Publisher)->peerConnection;
    auto peerConnection_s = _peerConnectionManager->getConnectionWithSession(streamRoomId, ConnectionType::Subscriber)->peerConnection;
    std::string keysIds;
    for(auto k: keys) keysIds += (k.keyId + ", ");
    LOG_DEBUG("STREAMS:WebRTC ", "updateKeys createWebRtcKeyStore");
    {
        std::unique_lock<std::shared_mutex> lock1(peerConnection_p->trackMutex);
        std::unique_lock<std::shared_mutex> lock2(peerConnection_s->trackMutex);
        peerConnection_s->keys = createWebRtcKeyStore(keys);
        peerConnection_p->keys = createWebRtcKeyStore(keys);
        LOG_DEBUG("STREAMS:WebRTC ", "updateKeys _peerConnectionObserver->UpdateCurrentKeys");
        // update input data keys 
        if(peerConnection_p->observer) peerConnection_p->observer->UpdateCurrentKeys(peerConnection_p->keys);
        if(peerConnection_s->observer) peerConnection_s->observer->UpdateCurrentKeys(peerConnection_s->keys);
    }
    LOG_DEBUG("STREAMS:WebRTC ", "updateKeys for_each->_audioTracks");
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
        LOG_DEBUG("STREAMS:WebRTC ", "updateKeys for_each->_videoTracks");
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
    peerConnection->pc = _peerConnectionFactory->Create(_configuration, _constraints);
    std::string streamId = streamRoomId + "-" + privmx::utils::Utils::getNowTimestampStr(); // TMP
    peerConnection->mediaStream = _peerConnectionFactory->CreateStream(streamId);
    peerConnection->pc->CreateLocalMediaStream(streamId);
    peerConnection->observer = std::make_shared<PmxPeerConnectionObserver>(_peerConnectionFactory, streamRoomId, privmx::webrtc::KeyStore::Create(std::vector<privmx::webrtc::Key>()), _frameCryptorOptions);
    peerConnection->pc->RegisterRTCPeerConnectionObserver(peerConnection->observer.get());
    return peerConnection;
}

void WebRTCImpl::setFrameCryptorOptions(const std::string& streamRoomId, const privmx::webrtc::FrameCryptorOptions& frameCryptorOptions) {
    auto connection = _peerConnectionManager->getConnectionWithSession(streamRoomId, ConnectionType::Subscriber);
    connection->peerConnection->observer->SetFrameCryptorOptions(frameCryptorOptions);
}

void WebRTCImpl::setOnTrackInterface(const std::string& streamRoomId, const std::optional<std::string>& streamId, std::shared_ptr<OnTrackInterface> onTrackInterface) {
    auto connection = _peerConnectionManager->getConnectionWithSession(streamRoomId, ConnectionType::Subscriber);
    if(streamId.has_value()) {
        connection->peerConnection->observer->addOnTrackInterfaceForSingleStream(streamId.value(), onTrackInterface);
    } else {
        connection->peerConnection->observer->setOnTrackInterface(onTrackInterface);
    }
}

std::optional<libwebrtc::scoped_refptr<libwebrtc::RTCDataChannel>> WebRTCImpl::createPeerConnectionWithLocalStream(
    const std::string& streamRoomId, 
    const std::vector<std::pair<std::string, libwebrtc::scoped_refptr<libwebrtc::RTCAudioTrack>>>& audioTracks,
    const std::vector<std::pair<std::string, libwebrtc::scoped_refptr<libwebrtc::RTCVideoTrack>>>& videoTracks,
    const std::optional<std::string>& dataChannel
) {
    _peerConnectionManager->initialize(streamRoomId, ConnectionType::Publisher);
    auto jc = _peerConnectionManager->getConnectionWithSession(streamRoomId, ConnectionType::Publisher);

    for(auto audioTrack: audioTracks) {
        AddAudioTrack(jc, audioTrack.second, privmx::utils::Hex::from(audioTrack.first));
    }
    for(auto videoTrack: videoTracks) {
        AddVideoTrack(jc, videoTrack.second, privmx::utils::Hex::from(videoTrack.first));
    }
    if(dataChannel.has_value()) {
        return AddDataChannel(jc, "JanusDataChannel");
    }
    return std::nullopt;
}

void WebRTCImpl::updatePeerConnectionWithLocalStream(
    const std::string& streamRoomId, 
    const std::vector<std::pair<std::string, libwebrtc::scoped_refptr<libwebrtc::RTCAudioTrack>>>& audioTracksToAdd,
    const std::vector<std::pair<std::string, libwebrtc::scoped_refptr<libwebrtc::RTCVideoTrack>>>& videoTracksToAdd,
    const std::vector<std::pair<std::string, libwebrtc::scoped_refptr<libwebrtc::RTCAudioTrack>>>& audioTracksToRemove,
    const std::vector<std::pair<std::string, libwebrtc::scoped_refptr<libwebrtc::RTCVideoTrack>>>& videoTracksToRemove,
    const std::optional<std::string>& dataChannel

) {
    _peerConnectionManager->initialize(streamRoomId, ConnectionType::Publisher);
    auto jc = _peerConnectionManager->getConnectionWithSession(streamRoomId, ConnectionType::Publisher);
    LOG_DEBUG("updatePeerConnectionWithLocalStream")
    for(auto audioTrack: audioTracksToRemove) {
        LOG_DEBUG("updatePeerConnectionWithLocalStream:audioTracksToRemove - ", audioTrack.first)
        RemoveAudioTrack(jc, privmx::utils::Hex::from(audioTrack.first));
    }
    for(auto videoTrack: videoTracksToRemove) {
        LOG_DEBUG("updatePeerConnectionWithLocalStream:videoTracksToRemove - ", videoTrack.first)
        RemoveVideoTrack(jc, privmx::utils::Hex::from(videoTrack.first));
    }
    for(auto audioTrack: audioTracksToAdd) {
        LOG_DEBUG("updatePeerConnectionWithLocalStream:audioTracksToAdd - ", audioTrack.first)
        AddAudioTrack(jc, audioTrack.second, privmx::utils::Hex::from(audioTrack.first));
    }
    for(auto videoTrack: videoTracksToAdd) {
        LOG_DEBUG("updatePeerConnectionWithLocalStream:videoTracksToAdd - ", videoTrack.first)
        AddVideoTrack(jc, videoTrack.second, privmx::utils::Hex::from(videoTrack.first));
    }
    if(jc->peerConnection->dataChannel.has_value() && !dataChannel.has_value()) {
        RemoveDataChannel(jc);
    } else if(!jc->peerConnection->dataChannel.has_value() && dataChannel.has_value()) {
        AddDataChannel(jc, dataChannel.value());
    }
    LOG_DEBUG("updatePeerConnectionWithLocalStream:pc->audioTracks -" , jc->peerConnection->audioTracks.size());
    LOG_DEBUG("updatePeerConnectionWithLocalStream:pc->videoTracks -" , jc->peerConnection->videoTracks.size());
}


void WebRTCImpl::AddAudioTrack(std::shared_ptr<privmx::endpoint::stream::JanusConnection> jc, libwebrtc::scoped_refptr<libwebrtc::RTCAudioTrack> audioTrack, std::string id) {
    jc->peerConnection->mediaStream->AddTrack(audioTrack);
    auto sender = jc->peerConnection->pc->AddTrack(audioTrack, libwebrtc::vector<libwebrtc::string>{std::vector<libwebrtc::string>{jc->peerConnection->mediaStream->id()}});
    std::shared_ptr<privmx::webrtc::FrameCryptor> frameCryptor;
    {
        std::shared_lock<std::shared_mutex> lock(jc->peerConnection->trackMutex);
        frameCryptor = privmx::webrtc::FrameCryptorFactory::frameCryptorFromRtpSender(
            _peerConnectionFactory,
            sender, 
            jc->peerConnection->keys,
            _frameCryptorOptions
        );
    }
    {
        std::unique_lock<std::shared_mutex> lock(jc->peerConnection->trackMutex);
        jc->peerConnection->audioTracks.insert(std::make_pair(
            id, 
            AudioTrackInfo{
                .track=audioTrack, 
                .sender=sender, 
                .frameCryptor=frameCryptor
            }
        ));
    }
}

void WebRTCImpl::AddVideoTrack(std::shared_ptr<privmx::endpoint::stream::JanusConnection> jc, libwebrtc::scoped_refptr<libwebrtc::RTCVideoTrack> videoTrack, std::string id) {
    jc->peerConnection->mediaStream->AddTrack(videoTrack);
    auto sender = jc->peerConnection->pc->AddTrack(videoTrack, libwebrtc::vector<libwebrtc::string>{std::vector<libwebrtc::string>{jc->peerConnection->mediaStream->id()}});
    std::shared_ptr<privmx::webrtc::FrameCryptor> frameCryptor;
    {
        std::shared_lock<std::shared_mutex> lock(jc->peerConnection->trackMutex);
        frameCryptor = privmx::webrtc::FrameCryptorFactory::frameCryptorFromRtpSender(
            _peerConnectionFactory,
            sender, 
            jc->peerConnection->keys,
            _frameCryptorOptions
        );
    }
    {
        std::unique_lock<std::shared_mutex> lock(jc->peerConnection->trackMutex);
        jc->peerConnection->videoTracks.insert(std::make_pair(
            id, 
            VideoTrackInfo{
                .track=videoTrack, 
                .sender=sender, 
                .frameCryptor=frameCryptor
            }
        ));
    }
}

libwebrtc::scoped_refptr<libwebrtc::RTCDataChannel> WebRTCImpl::AddDataChannel(std::shared_ptr<privmx::endpoint::stream::JanusConnection> jc, std::string id) {

    std::shared_ptr<libwebrtc::RTCDataChannelInit> rtcDataChannelInit = std::make_shared<libwebrtc::RTCDataChannelInit>();
    auto dataChannel = jc->peerConnection->pc->CreateDataChannel(id, rtcDataChannelInit.get());
    auto observer = std::make_shared<PmxDataChannelObserver>(nullptr, id);
    dataChannel->RegisterObserver(observer.get());
    jc->peerConnection->dataChannel = DataChannelInfo{rtcDataChannelInit, dataChannel, observer};
    return dataChannel;
}

void WebRTCImpl::RemoveAudioTrack(std::shared_ptr<privmx::endpoint::stream::JanusConnection> jc, std::string id) {
    std::unique_lock<std::shared_mutex> lock(jc->peerConnection->trackMutex);
    auto it = jc->peerConnection->audioTracks.find(id);
    if(it != jc->peerConnection->audioTracks.end()) {
        jc->peerConnection->mediaStream->RemoveTrack(it->second.track);
        jc->peerConnection->pc->RemoveTrack(it->second.sender);
        jc->peerConnection->audioTracks.erase(it);
    } else {
        throw IncorrectTrackIdException();
    }
}

void WebRTCImpl::RemoveVideoTrack(std::shared_ptr<privmx::endpoint::stream::JanusConnection> jc, std::string id) {
    std::unique_lock<std::shared_mutex> lock(jc->peerConnection->trackMutex);
    auto it = jc->peerConnection->videoTracks.find(id);
    if(it != jc->peerConnection->videoTracks.end()) {
        jc->peerConnection->mediaStream->RemoveTrack(it->second.track);
        jc->peerConnection->pc->RemoveTrack(it->second.sender);
        jc->peerConnection->videoTracks.erase(it);
    } else {
        throw IncorrectTrackIdException();
    }
}

void WebRTCImpl::RemoveDataChannel(std::shared_ptr<privmx::endpoint::stream::JanusConnection> jc) {
    if(jc->peerConnection->dataChannel.has_value()) {
        jc->peerConnection->dataChannel.value().channel->Close();
        jc->peerConnection->dataChannel = std::nullopt;
    }
}
