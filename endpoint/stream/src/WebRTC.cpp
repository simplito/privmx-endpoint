#include "privmx/endpoint/stream/WebRTC.hpp"
#include "privmx/endpoint/stream/StreamException.hpp"
#include <future>
#include <privmx/utils/Debug.hpp>

using namespace privmx::endpoint::stream;

WebRTC::WebRTC(
    libwebrtc::scoped_refptr<libwebrtc::RTCPeerConnection> peerConnection, 
    std::shared_ptr<PmxPeerConnectionObserver> peerConnectionObserver,
    libwebrtc::scoped_refptr<libwebrtc::RTCMediaConstraints> constraints
) :
    _peerConnection(peerConnection),
    _peerConnectionObserver(peerConnectionObserver),
    _constraints(constraints)
{
    _currentWebRtcKeys = privmx::webrtc::KeyStore::Create(std::vector<privmx::webrtc::Key>());
}

WebRTC::~WebRTC() {
    _peerConnection.release();
    _peerConnectionObserver.reset();
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
    _webRtcKeyUpdateCallbacks.clear();
    _peerConnection->Close();
}

std::shared_ptr<privmx::webrtc::KeyStore> WebRTC::getCurrentKeys() {
    return _currentWebRtcKeys;
}

void WebRTC::updateKeys(const std::vector<Key>& keys) {
    _currentWebRtcKeys =  createWebRtcKeyStore(keys);
    _peerConnectionObserver->UpdateCurrentKeys(_currentWebRtcKeys);
    _webRtcKeyUpdateCallbacks.forAll([&]([[maybe_unused]] int64_t key, std::function<void (std::shared_ptr<privmx::webrtc::KeyStore>)> value) {
        value(_currentWebRtcKeys);
    });
}

int64_t WebRTC::addKeyUpdateCallback(std::function<void(std::shared_ptr<privmx::webrtc::KeyStore>)> keyUpdateCallback) {
    int64_t id = ++_nextKeyUpdateCallbackId;
    _webRtcKeyUpdateCallbacks.set(id, keyUpdateCallback);
    return id;
}

void WebRTC::removeKeyUpdateCallback(int64_t keyUpdateCallbackId) {
    _webRtcKeyUpdateCallbacks.erase(keyUpdateCallbackId);
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