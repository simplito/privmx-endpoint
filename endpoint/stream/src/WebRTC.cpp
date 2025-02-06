#include "privmx/endpoint/stream/WebRTC.hpp"

using namespace privmx::endpoint::stream;

WebRTC::WebRTC(libwebrtc::scoped_refptr<libwebrtc::RTCPeerConnection> peerConnection) : _peerConnection(peerConnection), _peerConnectionObserver(peerConnectionObserver) {}

std::string WebRTC::createOfferAndSetLocalDescription() {
    std::promise<std::string> t_spd = std::promise<std::string>();
    peerConnection->CreateOffer(
        [&](const libwebrtc::string sdp, [[maybe_unused]] const libwebrtc::string type) {
            t_spd.set_value(sdp.std_string());
        },
        [&](const char* error) {
            throw stream::WebRTCException("SdpCreateFailure" + std::string(error));
        }, 
        _constraints
    );
    std::string sdp = t_spd.get_future().get();
    peerConnection->SetLocalDescription(
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
    peerConnection->SetRemoteDescription(
        sdp, 
        type,
        [&]() {}, 
        [&](const char* error) {
            throw stream::WebRTCException("OnSetSdpFailure" + std::string(error));
        }
    );
    // Create answer
    std::promise<std::string> t_spd = std::promise<std::string>();
    peerConnection->CreateAnswer(
        [&](const libwebrtc::string sdp, [[maybe_unused]] const libwebrtc::string type) {
            t_spd.set_value(sdp.std_string());
        },
        [&](const char* error) {
            throw stream::WebRTCException("SdpCreateFailure" + std::string(error));
        }, 
        _constraints
    );
    std::string sdp2 = t_spd.get_future().get();
    peerConnection->SetLocalDescription(
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
    peerConnection->SetRemoteDescription(
        sdp, 
        type,
        [&]() {}, 
        [&](const char* error) {
            throw stream::WebRTCException("OnSetSdpFailure" + std::string(error));
        }
    );
}

void WebRTC::close() {
    _peerConnection->Close();
}

void WebRTC::updateKeys(const std::vector<Key>& keys) {

}
