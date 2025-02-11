#include "privmx/endpoint/stream/WebRTC.hpp"
#include "privmx/endpoint/stream/StreamException.hpp"
#include <future>
#include <privmx/utils/Debug.hpp>

using namespace privmx::endpoint::stream;

WebRTC::WebRTC(
    libwebrtc::scoped_refptr<libwebrtc::RTCPeerConnectionFactory> peerConnectionFactory,
    libwebrtc::scoped_refptr<libwebrtc::RTCMediaConstraints> constraints,
    libwebrtc::RTCConfiguration configuration,
    int64_t streamId,
    std::optional<std::function<void(int64_t, int64_t, std::shared_ptr<Frame>, const std::string&)>> OnFrame
) :
    _peerConnectionFactory(peerConnectionFactory),
    _constraints(constraints),
    _peerConnection(_peerConnectionFactory->Create(configuration, constraints)),
    _peerConnectionObserver(std::make_shared<PmxPeerConnectionObserver>(streamId, privmx::webrtc::KeyStore::Create(std::vector<privmx::webrtc::Key>()), OnFrame)),
    _streamId(streamId)
{
    _currentWebRtcKeys = privmx::webrtc::KeyStore::Create(std::vector<privmx::webrtc::Key>());
    _peerConnection->RegisterRTCPeerConnectionObserver(_peerConnectionObserver.get());
}

WebRTC::~WebRTC() {
    _peerConnectionFactory->Delete(_peerConnection);
}

std::string WebRTC::createOfferAndSetLocalDescription() {
    std::promise<std::string> t_spd = std::promise<std::string>();
    _peerConnection->CreateOffer(
        [&](const libwebrtc::string sdp, [[maybe_unused]] const libwebrtc::string type) {
            t_spd.set_value(sdp.std_string());
        },
        [&](const char* error) {
            throw stream::WebRTCException("SdpCreateFailure" + std::string(error));
        }, 
        _constraints
    );
    std::string sdp = t_spd.get_future().get();
    _peerConnection->SetLocalDescription(
        sdp, 
        "offer", 
        []() {}, 
        [](const char* error) {
            throw stream::WebRTCException("OnSetSdpFailure" + std::string(error));
        }
    );
    return sdp;
}

std::string WebRTC::createAnswerAndSetDescriptions(const std::string& sdp, const std::string& type) {
    // Set remote description
    _peerConnection->SetRemoteDescription(
        sdp, 
        type,
        [&]() {}, 
        [&](const char* error) {
            throw stream::WebRTCException("OnSetSdpFailure" + std::string(error));
        }
    );
    // Create answer
    std::promise<std::string> t_spd = std::promise<std::string>();
    _peerConnection->CreateAnswer(
        [&](const libwebrtc::string sdp, [[maybe_unused]] const libwebrtc::string type) {
            t_spd.set_value(sdp.std_string());
        },
        [&](const char* error) {
            throw stream::WebRTCException("SdpCreateFailure" + std::string(error));
        }, 
        _constraints
    );
    std::string sdp2 = t_spd.get_future().get();
    _peerConnection->SetLocalDescription(
        sdp2, 
        "answer",
        [&]() {}, 
        [&](const char* error) {
            throw stream::WebRTCException("OnSetSdpFailure" + std::string(error));
        }
    );
    return sdp2;
}

void WebRTC::setAnswerAndSetRemoteDescription(const std::string& sdp, const std::string& type) {
    _peerConnection->SetRemoteDescription(
        sdp, 
        type,
        [&]() {}, 
        [&](const char* error) {
            throw stream::WebRTCException("OnSetSdpFailure" + std::string(error));
        }
    );
}

void WebRTC::close() {
    PRIVMX_DEBUG("STREAMS", "WebRTC_IMPL", "WebRTC::close()");
    _frameCryptors.clear();
    _peerConnection->Close();
}

void WebRTC::updateKeys(const std::vector<Key>& keys) {
    _currentWebRtcKeys =  createWebRtcKeyStore(keys);
    _peerConnectionObserver->UpdateCurrentKeys(_currentWebRtcKeys);
    for(size_t i = 0; i < _frameCryptors.size(); i++) {
        _frameCryptors[i]->setKeyStore(_currentWebRtcKeys);
    }
}

void WebRTC::AddTrack(libwebrtc::scoped_refptr<libwebrtc::RTCAudioTrack> audioTrack) {
    auto sender = _peerConnection->AddTrack(audioTrack, libwebrtc::vector<libwebrtc::string>{std::vector<libwebrtc::string>{std::to_string(_streamId)}});
    std::shared_ptr<privmx::webrtc::FrameCryptor> frameCryptor = privmx::webrtc::FrameCryptorFactory::frameCryptorFromRtpSender(
        sender, 
       _currentWebRtcKeys
    );
    _frameCryptors.push_back(frameCryptor);

}
void WebRTC::AddTrack(libwebrtc::scoped_refptr<libwebrtc::RTCVideoTrack> videoTrack) {
    auto sender = _peerConnection->AddTrack(videoTrack, libwebrtc::vector<libwebrtc::string>{std::vector<libwebrtc::string>{std::to_string(_streamId)}});
    std::shared_ptr<privmx::webrtc::FrameCryptor> frameCryptor = privmx::webrtc::FrameCryptorFactory::frameCryptorFromRtpSender(
        sender, 
        _currentWebRtcKeys
    );
    _frameCryptors.push_back(frameCryptor);
}

std::shared_ptr<privmx::webrtc::KeyStore> WebRTC::createWebRtcKeyStore(const std::vector<privmx::endpoint::stream::Key>& keys) {
    std::vector<privmx::webrtc::Key> webRtcKeys;
    for(size_t i = 0; i < keys.size(); i++) {
        webRtcKeys.push_back(
            privmx::webrtc::Key{.
                keyId=keys[i].keyId, 
                .key=keys[i].key, 
                .type=keys[i].type == privmx::endpoint::stream::KeyType::REMOTE ? privmx::webrtc::KeyType::REMOTE : privmx::webrtc::KeyType::LOCAL
            }
        );
    }
    return privmx::webrtc::KeyStore::Create(webRtcKeys);
}