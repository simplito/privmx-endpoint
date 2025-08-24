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
    privmx::webrtc::FrameCryptorOptions frameCryptorOptions,
    std::optional<std::function<void(int64_t, int64_t, std::shared_ptr<Frame>, const std::string&)>> OnFrame
    
) 
:
    _peerConnectionFactory(peerConnectionFactory),
    _constraints(constraints),
    _peerConnection(_peerConnectionFactory->Create(configuration, constraints)),
    // _mediaStream(_peerConnectionFactory->CreateStream(std::to_string(streamId))),
    _frameCryptorOptions(frameCryptorOptions),
    _peerConnectionObserver(std::make_shared<PmxPeerConnectionObserver>(peerConnectionFactory, streamId, privmx::webrtc::KeyStore::Create(std::vector<privmx::webrtc::Key>()), OnFrame, _frameCryptorOptions)),
    _streamId(streamId)
{
    std::cout << "========================> WEBRTC constructor\n************************\n*********************\n****************" << std::endl;
    std::cout << __LINE__ << std::endl;
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
    _videoTracks.clear();
    _audioTracks.clear();
    _peerConnection->Close();
}

void WebRTC::updateKeys(const std::vector<Key>& keys) {
    _currentWebRtcKeys =  createWebRtcKeyStore(keys);
    _peerConnectionObserver->UpdateCurrentKeys(_currentWebRtcKeys);
    std::for_each(
        _audioTracks.begin(),
        _audioTracks.end(), 
        [&](const auto& p) {p.second.frameCryptor->setKeyStore(_currentWebRtcKeys);}
    );
    std::for_each(
        _videoTracks.begin(),
        _videoTracks.end(), 
        [&](const auto& p) {p.second.frameCryptor->setKeyStore(_currentWebRtcKeys);}
    );
}

void WebRTC::AddAudioTrack(libwebrtc::scoped_refptr<libwebrtc::RTCAudioTrack> audioTrack, int64_t id) {
    if (! _mediaStream) {
        std::cout << "creating media stream..." << std::endl;
        _mediaStream = _peerConnectionFactory->CreateStream(/**std::to_string(_streamId)*/"my_stream");
        std::cout << "created." << std::endl;
    }
    if (!_mediaStream) {
        throw std::runtime_error("createStream returned null!");
    }
    std::cout << "AddAudioTrack.... \n*******************\n*******************\n***************" << std::endl;
    _mediaStream->AddTrack(audioTrack);
    std::cout << "Added to mediaStream" << std::endl;

    std::cout <<  "Adding to peerConnection... with streamId: " << _streamId << std::endl;
    
    std::string streamIdStr {std::to_string(_streamId)};
    std::vector<std::string> ids {};
    ids.push_back(streamIdStr);

    std::cout << "Debug of audioTrack" << std::endl;
    auto state = audioTrack->state();
    auto isEnabled = audioTrack->enabled();
    std::cout << "TrackState: " << (state == 0 ? "alive" : "ended") << " / enabled: " << isEnabled << std::endl;

    auto sender = _peerConnection->AddTrack(audioTrack, ids);
    std::cout <<  "Added to peerConnection." << std::endl;

    std::cout << "Create cryptor..." << std::endl;
    std::shared_ptr<privmx::webrtc::FrameCryptor> frameCryptor = privmx::webrtc::FrameCryptorFactory::frameCryptorFromRtpSender(
        _peerConnectionFactory,
        sender, 
        _currentWebRtcKeys,
        _frameCryptorOptions
    );

    std::cout << "Cryptor created." << std::endl;
    _audioTracks.insert(std::make_pair(
        id, 
        AudioTrackInfo{
            .track=audioTrack, 
            .sender=sender, 
            .frameCryptor=frameCryptor
        }
    ));

}

void WebRTC::AddVideoTrack(libwebrtc::scoped_refptr<libwebrtc::RTCVideoTrack> videoTrack, int64_t id) {
    // if (! _mediaStream) {
    //     _mediaStream = _peerConnectionFactory->CreateStream(std::to_string(_streamId));
    // }
    _mediaStream->AddTrack(videoTrack);
    auto sender = _peerConnection->AddTrack(videoTrack, std::vector<std::string>{std::to_string(_streamId)});
    std::shared_ptr<privmx::webrtc::FrameCryptor> frameCryptor = privmx::webrtc::FrameCryptorFactory::frameCryptorFromRtpSender(
        _peerConnectionFactory,
        sender, 
        _currentWebRtcKeys,
        _frameCryptorOptions
    );
    _videoTracks.insert(std::make_pair(
        id, 
        VideoTrackInfo{
            .track=videoTrack, 
            .sender=sender, 
            .frameCryptor=frameCryptor
        }
    ));
}

void WebRTC::RemoveAudioTrack(int64_t id) {
    auto it = _audioTracks.find(id);
    if(it != _audioTracks.end()) {
        _mediaStream->RemoveTrack(it->second.track);
        _peerConnection->RemoveTrack(it->second.sender);
        _audioTracks.erase(it);
    } else {
        throw IncorrectTrackIdException();
    }
}

void WebRTC::RemoveVideoTrack(int64_t id) {
    auto it = _videoTracks.find(id);
    if(it != _videoTracks.end()) {
        _mediaStream->RemoveTrack(it->second.track);
        _peerConnection->RemoveTrack(it->second.sender);
        _videoTracks.erase(it);
    } else {
        throw IncorrectTrackIdException();
    }
}

std::shared_ptr<privmx::webrtc::KeyStore> WebRTC::createWebRtcKeyStore(const std::vector<privmx::endpoint::stream::Key>& keys) {
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

void WebRTC::setCryptorOptions(const privmx::webrtc::FrameCryptorOptions& options) {
    _frameCryptorOptions = options;
    std::for_each(
        _audioTracks.begin(),
        _audioTracks.end(), 
        [&](const auto& p) {p.second.frameCryptor->setOptions(_frameCryptorOptions);}
    );
    std::for_each(
        _videoTracks.begin(),
        _videoTracks.end(), 
        [&](const auto& p) {p.second.frameCryptor->setOptions(_frameCryptorOptions);}
    );
}