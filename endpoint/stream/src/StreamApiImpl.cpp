/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/endpoint/core/JsonSerializer.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/EventVarSerializer.hpp>
#include <privmx/endpoint/core/EndpointUtils.hpp>
#include <privmx/utils/Debug.hpp>

#include "privmx/endpoint/stream/StreamApiImpl.hpp"
#include "privmx/endpoint/stream/StreamTypes.hpp"
#include "privmx/endpoint/stream/StreamException.hpp"
#include "privmx/endpoint/stream/DynamicTypes.hpp"
#include "privmx/endpoint/stream/WebRTC.hpp"


#include <libwebrtc.h>
#include <rtc_audio_device.h>
#include <rtc_peerconnection.h>
#include <base/portable.h>
#include <rtc_mediaconstraints.h>
#include <rtc_peerconnection.h>
#include <pmx_frame_cryptor.h>

using namespace privmx::endpoint;
using namespace privmx::endpoint::stream;

StreamApiImpl::StreamApiImpl(
    const privfs::RpcGateway::Ptr& gateway,
    const privmx::crypto::PrivateKey& userPrivKey,
    const std::shared_ptr<core::KeyProvider>& keyProvider,
    const std::string& host,
    const std::shared_ptr<core::EventMiddleware>& eventMiddleware,
    const std::shared_ptr<core::EventChannelManager>& eventChannelManager,
    const std::shared_ptr<core::InternalContextEventManager>& internalContextEventManager
) : _gateway(gateway),
    _userPrivKey(userPrivKey),
    _keyProvider(keyProvider),
    _host(host),
    _eventMiddleware(eventMiddleware),
    _internalContextEventManager(internalContextEventManager),
    _serverApi(std::make_shared<ServerApi>(gateway)),
    _streamSubscriptionHelper(core::SubscriptionHelper(eventChannelManager, "stream", "streams")) 
    
{
    // streamGetTurnCredentials
    auto model = utils::TypedObjectFactory::createNewObject<server::StreamGetTurnCredentialsModel>();
    auto credentials = _serverApi->streamGetTurnCredentials(model).credentials();
    libwebrtc::LibWebRTC::Initialize();
    _peerConnectionFactory = libwebrtc::LibWebRTC::CreateRTCPeerConnectionFactory();
    _configuration = libwebrtc::RTCConfiguration();
    for(size_t i = 0; i < credentials.size(); i++) {
        libwebrtc::IceServer iceServer = {
            .uri=credentials.get(i).url(), 
            .username=portable::string(credentials.get(i).username()), 
            .password=portable::string(credentials.get(i).password())
        };
        _configuration.ice_servers[i] = iceServer;
    }
    _constraints = libwebrtc::RTCMediaConstraints::Create();
    _api = std::make_shared<StreamApiLowImpl>(gateway, userPrivKey, keyProvider, host, eventMiddleware, eventChannelManager, internalContextEventManager);
}


int64_t StreamApiImpl::createStream(const std::string& streamRoomId) {
    int64_t streamId = generateNumericId();
    auto peerConnection = _peerConnectionFactory->Create(
        _configuration, 
        _constraints
    );
    auto peerConnectionObserver = std::make_shared<PmxPeerConnectionObserver>(
        streamId,
        privmx::webrtc::KeyStore::Create(std::vector<privmx::webrtc::Key>()),
        []([[maybe_unused]] int64_t w, [[maybe_unused]] int64_t h, [[maybe_unused]] std::shared_ptr<Frame> frame, [[maybe_unused]] const std::string& id) {}
    );
    std::shared_ptr<WebRTC> peerConnectionWebRTC = std::make_shared<WebRTC>(peerConnection, peerConnectionObserver, _constraints);
    
    _streamDataMap3.set( streamId, peerConnectionWebRTC);
    peerConnection->RegisterRTCPeerConnectionObserver(peerConnectionObserver.get());
    _api->createStream(streamRoomId, streamId, peerConnectionWebRTC);
    return streamId;
}

// Adding track
std::vector<std::pair<int64_t, std::string>> StreamApiImpl::listAudioRecordingDevices() {  
    std::string name, deviceId;
    name.resize(255);
    deviceId.resize(255);
    libwebrtc::scoped_refptr<libwebrtc::RTCAudioDevice> audioDevice = _peerConnectionFactory->GetAudioDevice();
    uint32_t num = audioDevice->RecordingDevices();
    std::vector<std::pair<int64_t, std::string>> result;
    for (uint32_t i = 0; i < num; ++i) {
        audioDevice->RecordingDeviceName(i, (char*)name.data(), (char*)deviceId.data());
        result.push_back(std::make_pair((int64_t)i, name));
    }
    return result;
}

std::vector<std::pair<int64_t, std::string>> StreamApiImpl::listVideoRecordingDevices() {
    std::string name, deviceId;
    name.resize(255);
    deviceId.resize(255);
    libwebrtc::scoped_refptr<libwebrtc::RTCVideoDevice> videoDevice = _peerConnectionFactory->GetVideoDevice();
    uint32_t num = videoDevice->NumberOfDevices();
    std::vector<std::pair<int64_t, std::string>> result;
    for (uint32_t i = 0; i < num; ++i) {
        videoDevice->GetDeviceName(i, (char*)name.data(), name.size(), (char*)deviceId.data(), deviceId.size());
        result.push_back(std::make_pair((int64_t)i, name));
    }
    return result;
}

std::vector<std::pair<int64_t, std::string>> StreamApiImpl::listDesktopRecordingDevices() {
   throw stream::NotImplementedException();
}
// int64_t id, DeviceType type, const std::string& params_JSON can be merged to one struct [Track info]
void StreamApiImpl::trackAdd(int64_t streamId, DeviceType type, int64_t id, const std::string& params_JSON) {
    switch (type) {
        case DeviceType::Audio :
            return trackAddAudio(streamId, id, params_JSON);
        case DeviceType::Video :
            return trackAddVideo(streamId, id, params_JSON);
        case DeviceType::Desktop :
            return trackAddDesktop(streamId, id, params_JSON);
    }
}

void StreamApiImpl::trackAddAudio(int64_t streamId, int64_t id, const std::string& params_JSON) {
    libwebrtc::scoped_refptr<libwebrtc::RTCAudioDevice> audioDevice = _peerConnectionFactory->GetAudioDevice();
    audioDevice->SetRecordingDevice(id);
    auto audioSource = _peerConnectionFactory->CreateAudioSource("audio_source");
    auto audioTrack = _peerConnectionFactory->CreateAudioTrack(audioSource, "audio_track");
    audioTrack->SetVolume(10);
    // Add tracks to the peer connection
    auto webrtcOpt = _streamDataMap3.get(streamId);
    if(!webrtcOpt.has_value()) {
        throw IncorrectStreamIdException();
    }
    auto webrtc = webrtcOpt.value();
    auto peerConnection = webrtc->getPeerConnection();
    auto sender = peerConnection->AddTrack(audioTrack, libwebrtc::vector<libwebrtc::string>{std::vector<libwebrtc::string>{std::to_string(streamId)}});
    // std::shared_ptr<privmx::webrtc::FrameCryptor> frameCryptor = privmx::webrtc::FrameCryptorFactory::frameCryptorFromRtpSender(
    //     sender, 
    //     privmx::webrtc::KeyStore::Create(std::vector<privmx::webrtc::Key>())
    // );
    // webrtc->addKeyUpdateCallback([frameCryptor](std::shared_ptr<privmx::webrtc::KeyStore> keys) {
    //     frameCryptor->setKeyStore(keys);
    // });

}

void StreamApiImpl::trackAddVideo(int64_t streamId, int64_t id, const std::string& params_JSON) {
    libwebrtc::scoped_refptr<libwebrtc::RTCVideoDevice> videoDevice = _peerConnectionFactory->GetVideoDevice();
    // params_JSON
    libwebrtc::scoped_refptr<libwebrtc::RTCVideoCapturer> videoCapturer = videoDevice->Create("video_capturer", id, 1280, 720, 30);
    libwebrtc::scoped_refptr<libwebrtc::RTCVideoSource> videoSource = _peerConnectionFactory->CreateVideoSource(videoCapturer, "video_source", _constraints);
    libwebrtc::scoped_refptr<libwebrtc::RTCVideoTrack> videoTrack = _peerConnectionFactory->CreateVideoTrack(videoSource, "video_track");

    // Add tracks to the peer connection
    auto webrtcOpt = _streamDataMap3.get(streamId);
    if(!webrtcOpt.has_value()) {
        throw IncorrectStreamIdException();
    }
    auto webrtc = webrtcOpt.value();
    auto peerConnection = webrtc->getPeerConnection();
    auto sender = peerConnection->AddTrack(videoTrack, libwebrtc::vector<libwebrtc::string>{std::vector<libwebrtc::string>{std::to_string(streamId)}});
    // std::shared_ptr<privmx::webrtc::FrameCryptor> frameCryptor = privmx::webrtc::FrameCryptorFactory::frameCryptorFromRtpSender(
    //     sender, 
    //     privmx::webrtc::KeyStore::Create(std::vector<privmx::webrtc::Key>())
    // );
    // webrtc->addKeyUpdateCallback([frameCryptor](std::shared_ptr<privmx::webrtc::KeyStore> keys) {
    //     frameCryptor->setKeyStore(keys);
    // });
    // Start capture video
    videoCapturer->StartCapture();    
}

void StreamApiImpl::trackAddDesktop(int64_t streamId, int64_t id, const std::string& params_JSON) {
    throw stream::NotImplementedException();
}

// Publishing stream
void StreamApiImpl::publishStream(int64_t streamId) {
    _api->publishStream(streamId);
}

// Joining to Stream
int64_t StreamApiImpl::joinStream(const std::string& streamRoomId, const std::vector<int64_t>& streamsId, const streamJoinSettings& settings) {
    
    int64_t streamId = generateNumericId();
    auto peerConnection = _peerConnectionFactory->Create(
        _configuration, 
        _constraints
    );
    auto peerConnectionObserver = std::make_shared<PmxPeerConnectionObserver>(
        streamId,
        privmx::webrtc::KeyStore::Create(std::vector<privmx::webrtc::Key>()),
        settings.OnFrame.has_value() ? 
            settings.OnFrame.value() : 
            []([[maybe_unused]] int64_t w, [[maybe_unused]] int64_t h, [[maybe_unused]] std::shared_ptr<Frame> frame, [[maybe_unused]] const std::string& id) {}
    );
    std::shared_ptr<WebRTC> peerConnectionWebRTC = std::make_shared<WebRTC>(peerConnection, peerConnectionObserver, _constraints);

    _streamDataMap3.set( streamId, peerConnectionWebRTC);
    peerConnection->RegisterRTCPeerConnectionObserver(peerConnectionObserver.get());
    return _api->joinStream(streamRoomId, streamsId, settings, streamId, peerConnectionWebRTC);
}

std::vector<Stream> StreamApiImpl::listStreams(const std::string& streamRoomId) {
    auto model = privmx::utils::TypedObjectFactory::createNewObject<server::StreamListModel>();
    model.streamRoomId(streamRoomId);
    auto streamList = _serverApi->streamList(model).list();
    std::vector<Stream> result;
    for(auto stream: streamList) {
        result.push_back(Stream{.streamId=stream.streamId(),.userId=stream.userId()});
    }
    return result;
}

std::string StreamApiImpl::createStreamRoom(
    const std::string& contextId, 
    const std::vector<core::UserWithPubKey>& users, 
    const std::vector<core::UserWithPubKey>& managers,
    const core::Buffer& publicMeta, 
    const core::Buffer& privateMeta,
    const std::optional<core::ContainerPolicy>& policies
) {
    return _api->createStreamRoom(contextId, users, managers, publicMeta, privateMeta, policies);
}

void StreamApiImpl::updateStreamRoom(
    const std::string& streamRoomId, 
    const std::vector<core::UserWithPubKey>& users, 
    const std::vector<core::UserWithPubKey>&managers,
    const core::Buffer& publicMeta, 
    const core::Buffer& privateMeta, 
    const int64_t version, 
    const bool force, 
    const bool forceGenerateNewKey, 
    const std::optional<core::ContainerPolicy>& policies
) {
    _api->updateStreamRoom(streamRoomId, users, managers, publicMeta, privateMeta, version, force, forceGenerateNewKey, policies);
}

core::PagingList<StreamRoom> StreamApiImpl::listStreamRooms(const std::string& contextId, const core::PagingQuery& query) {
    return _api->listStreamRooms(contextId, query);
}

StreamRoom StreamApiImpl::getStreamRoom(const std::string& streamRoomId) {
    return _api->getStreamRoom(streamRoomId);
}

void StreamApiImpl::deleteStreamRoom(const std::string& streamRoomId) {
    _api->deleteStreamRoom(streamRoomId);
}

int64_t StreamApiImpl::generateNumericId() {
    return std::rand();
}

void StreamApiImpl::unpublishStream(int64_t streamId) {
    std::cout << "h1" << std::endl;
    _streamDataMap3.erase(streamId);
    std::cout << "h1" << std::endl;
    _api->unpublishStream(streamId);
}

void StreamApiImpl::leaveStream(int64_t streamId) {
    std::cout << "h2" << std::endl;
    _streamDataMap3.erase(streamId);
    std::cout << "h2" << std::endl;
    _api->leaveStream(streamId);
}