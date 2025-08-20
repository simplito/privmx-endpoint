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
#include "privmx/endpoint/stream/StreamApiLow.hpp"
#include "privmx/endpoint/stream/StreamException.hpp"
#include "privmx/endpoint/stream/WebRTC.hpp"


#include <libwebrtc.h>
#include <rtc_audio_device.h>
#include <rtc_audio_source.h>
#include <rtc_peerconnection.h>
#include <base/portable.h>
#include <rtc_mediaconstraints.h>
#include <rtc_peerconnection.h>
#include <pmx_frame_cryptor.h>

using namespace privmx::endpoint;
using namespace privmx::endpoint::stream;

void StreamApiImpl::ensureInitWebRtcLibraryUtils() {
    if (_webRtcLibraryUtilsInitialized == true) {
        return;
    }
    
    std::cout << "-> Create RTCConfiguration.." << std::endl;
    _configuration = libwebrtc::RTCConfiguration();
    
    std::cout << "-> Create constraints (empty - to be implemented).." << std::endl;
    _constraints = libwebrtc::RTCMediaConstraints::Create();
    std::cout << "-> Constraints created." << std::endl;

    std::cout << "-> Getting credentials.." << std::endl;
    auto credentials = _api->getTurnCredentials();

    std::cout << "-> Configure ICE.." << std::endl;
    for(size_t i = 0; i < credentials.size(); i++) {
        libwebrtc::IceServer iceServer = {
            .uri=credentials[i].url, 
            .username=portable::string(credentials[i].username), 
            .password=portable::string(credentials[i].password)
        };
        _configuration.ice_servers[i] = iceServer;
    }

    std::cout << "-> Set cryptors.." << std::endl;
    _frameCryptorOptions = privmx::webrtc::FrameCryptorOptions{.dropFrameIfCryptionFailed=false};
    
    _webRtcLibraryUtilsInitialized = true;
    std::cout << "-> Done." << std::endl;
}

StreamApiImpl::StreamApiImpl(core::Connection& connection, event::EventApi eventApi) {
    _api = std::make_shared<StreamApiLow>(StreamApiLow::create(connection, eventApi));

    std::cout << "-> Init libwebrtc.." << std::endl;
    libwebrtc::LibWebRTC::Initialize();

    std::cout << "-> Create peerConnFactory.." << std::endl;
    _peerConnectionFactory = libwebrtc::LibWebRTC::CreateRTCPeerConnectionFactory();

    _webRtcLibraryUtilsInitialized = false;
}

int64_t StreamApiImpl::createStream(const std::string& streamRoomId) {
    ensureInitWebRtcLibraryUtils();
    int64_t streamId = generateNumericId();

    std::cout << "-> Create WebRTC .." << std::endl;
    std::shared_ptr<WebRTC> peerConnectionWebRTC = std::make_shared<WebRTC>(_peerConnectionFactory, _constraints, _configuration, streamId, _frameCryptorOptions, std::nullopt);
    _streamDataMap.set( 
        streamId, 
        std::make_shared<StreamData>(
            peerConnectionWebRTC,
            privmx::utils::ThreadSaveMap<int64_t, libwebrtc::scoped_refptr<libwebrtc::RTCVideoCapturer>>(),
            StreamStatus::Offline
        )
    );
    std::cout << "-> WebRTC created." << std::endl;
    _api->createStream(streamRoomId, streamId, peerConnectionWebRTC);
    std::cout << "-> _api->createStream() called." << std::endl;
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
void StreamApiImpl::trackAdd(int64_t streamId, const TrackParam& track) {
    std::cout << "StreamApiImpl::trackAdd()..." << std::endl;
    switch (track.type) {
        case DeviceType::Audio :
            return trackAddAudio(streamId, track.id, track.params_JSON);
        case DeviceType::Video :
            return trackAddVideo(streamId, track.id, track.params_JSON);
        case DeviceType::Desktop :
            return trackAddDesktop(streamId, track.id, track.params_JSON);
    }
}

void StreamApiImpl::trackAddAudio(int64_t streamId, int64_t id, const std::string& params_JSON) {
    try {
        std::cout << "StreamApiImpl::trackAddAudio()..." << std::endl;
        auto audioDevice = _peerConnectionFactory->GetAudioDevice();
        std::cerr << __LINE__ << std::endl;
        // auto recDeviceResult = audioDevice->SetRecordingDevice(id);
        // if (recDeviceResult != 0) {
        //     std::cerr << "Cannot set recording device" << std::endl;
        // } else {
        //     std::cout << "Recording Device set." << std::endl;
        // }
        std::cerr << __LINE__ << std::endl;

        auto audioSource = _peerConnectionFactory->CreateAudioSource("audio_source");
        if (!audioSource) {
            throw std::runtime_error("createAudioSource() returned null!");
        } else {
            std::cout << "AudioSource created." << std::endl;
        }
        std::cout << "Creating AudioTrack..." << std::endl;
        auto audioTrack = _peerConnectionFactory->CreateAudioTrack(audioSource, "audio_track");
        if (!audioTrack) {
            throw std::runtime_error("CreateAudioTrack() returned null!");
        } else {
            std::cout << "AudioTrack created." << std::endl;
        }

        std::cerr << __LINE__ << std::endl;
        audioTrack->SetVolume(10);
        // Add tracks to the peer connection
        auto streamData = _streamDataMap.get(streamId);
        if(!streamData.has_value()) {
            throw IncorrectStreamIdException();
        }
        std::cerr << __LINE__ << std::endl;
        streamData.value()->webrtc->AddAudioTrack(audioTrack, id);
        std::cerr << __LINE__ << std::endl;

    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
    } catch (...) {
        std::cerr << "Error catched" << std::endl;
    }
}

void StreamApiImpl::trackAddVideo(int64_t streamId, int64_t id, const std::string& params_JSON) {
    std::cout << "StreamApiImpl::trackAddVideo..." << std::endl;
    
    std::cout << "_peerConnectionFactory->GetVideoDevice()..." << std::endl;
    libwebrtc::scoped_refptr<libwebrtc::RTCVideoDevice> videoDevice = _peerConnectionFactory->GetVideoDevice();

    // params_JSON    
    std::cout << "videoDevice->Create()..." << std::endl;
    libwebrtc::scoped_refptr<libwebrtc::RTCVideoCapturer> videoCapturer = videoDevice->Create("video_capturer", id, 1280, 720, 30);
        std::cout << "videoDevice->CreateVideoSource()..." << std::endl;
    libwebrtc::scoped_refptr<libwebrtc::RTCVideoSource> videoSource = _peerConnectionFactory->CreateVideoSource(videoCapturer, "video_source", _constraints);
        std::cout << "videoDevice->CreateVideoTrack()..." << std::endl;
    // libwebrtc::scoped_refptr<libwebrtc::RTCVideoTrack> videoTrack = _peerConnectionFactory->CreateVideoTrack(videoSource, "video_track");

    // // Add tracks to the peer connection
    // auto streamData = _streamDataMap.get(streamId);
    // if(!streamData.has_value()) {
    //     throw IncorrectStreamIdException();
    // }
    // streamData.value()->webrtc->AddVideoTrack(videoTrack, id);
    // std::lock_guard<std::mutex> lock(streamData.value()->streamMutex);
    // streamData.value()->streamCapturers.set(id, videoCapturer);
    // std::cerr << __LINE__ << std::endl;
    // if(streamData.value()->status == StreamStatus::Online) {
    //     std::cerr << __LINE__ << std::endl;
    //     videoCapturer->StartCapture();
    // }
    // std::cerr << __LINE__ << std::endl;
    // // if stream is published start Capture if not dont

}

void StreamApiImpl::trackAddDesktop(int64_t streamId, int64_t id, const std::string& params_JSON) {
    throw stream::NotImplementedException();
}

void StreamApiImpl::trackRemove(int64_t streamId, const Track& track) {
    switch (track.type) {
        case DeviceType::Audio :
            return trackRemoveAudio(streamId, track.id);
        case DeviceType::Video :
            return trackRemoveVideo(streamId, track.id);
        case DeviceType::Desktop :
            return trackRemoveDesktop(streamId, track.id);
    }
}

void StreamApiImpl::trackRemoveAudio(int64_t streamId, int64_t id) {
    auto streamData = _streamDataMap.get(streamId);
    if(!streamData.has_value()) {
        throw IncorrectStreamIdException();
    }
    streamData.value()->webrtc->RemoveAudioTrack(id);
}

void StreamApiImpl::trackRemoveVideo(int64_t streamId, int64_t id) {
    auto streamData = _streamDataMap.get(streamId);
    if(!streamData.has_value()) {
        throw IncorrectStreamIdException();
    }
    streamData.value()->webrtc->RemoveVideoTrack(id);
    std::lock_guard<std::mutex> lock(streamData.value()->streamMutex);
    streamData.value()->streamCapturers.erase(id);
}

void StreamApiImpl::trackRemoveDesktop(int64_t streamId, int64_t id) {
    throw stream::NotImplementedException();
}

// Publishing stream
void StreamApiImpl::publishStream(int64_t streamId) {
    auto streamData = _streamDataMap.get(streamId);
    if(!streamData.has_value()) {
        throw IncorrectStreamIdException();
    }
    std::lock_guard<std::mutex> lock(streamData.value()->streamMutex);
    streamData.value()->status = StreamStatus::Online;
    streamData.value()->streamCapturers.forAll([&]([[maybe_unused]]const int64_t& id, const libwebrtc::scoped_refptr<libwebrtc::RTCVideoCapturer>& videoCapturer) {
        videoCapturer->StartCapture();
    });
    _api->publishStream(streamId);
}

// Joining to Stream
int64_t StreamApiImpl::joinStream(const std::string& streamRoomId, const std::vector<int64_t>& streamsId, const StreamJoinSettings& settings) {
    int64_t streamId = generateNumericId();
    std::shared_ptr<WebRTC> peerConnectionWebRTC = std::make_shared<WebRTC>(_peerConnectionFactory, _constraints, _configuration, streamId, _frameCryptorOptions, settings.OnFrame);
    _streamDataMap.set( 
        streamId, 
        std::make_shared<StreamData>(
            peerConnectionWebRTC,
            privmx::utils::ThreadSaveMap<int64_t, libwebrtc::scoped_refptr<libwebrtc::RTCVideoCapturer>>(),
            StreamStatus::Online
        )
    );
    return _api->joinStream(streamRoomId, streamsId, settings.settings, streamId, peerConnectionWebRTC);
}

std::vector<Stream> StreamApiImpl::listStreams(const std::string& streamRoomId) {
    return _api->listStreams(streamRoomId);
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
    _api->unpublishStream(streamId);
    _streamDataMap.erase(streamId);
}

void StreamApiImpl::leaveStream(int64_t streamId) {
    _api->leaveStream(streamId);
    _streamDataMap.erase(streamId);
}

void StreamApiImpl::subscribeForStreamEvents() {
    _api->subscribeForStreamEvents();
}

void StreamApiImpl::unsubscribeFromStreamEvents() {
    _api->unsubscribeFromStreamEvents();
}

void StreamApiImpl::keyManagement(bool disable) {
    _api->keyManagement(disable);
}

void StreamApiImpl::dropBrokenFrames(bool enable) {
    _frameCryptorOptions = privmx::webrtc::FrameCryptorOptions{.dropFrameIfCryptionFailed=enable};
    _streamDataMap.forAll([&]([[maybe_unused]]const uint64_t &id, const std::shared_ptr<StreamData>& streamData) {
        streamData->webrtc->setCryptorOptions(_frameCryptorOptions);
    });
}

void StreamApiImpl::reconfigureStream(int64_t localStreamId, const std::string& optionsJSON) {
    _api->reconfigureStream(localStreamId, optionsJSON);
}