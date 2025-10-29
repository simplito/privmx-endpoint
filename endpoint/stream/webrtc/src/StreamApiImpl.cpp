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


#include <libwebrtc.h>
#include <rtc_audio_device.h>
#include <rtc_peerconnection.h>
#include <base/portable.h>
#include <rtc_mediaconstraints.h>
#include <rtc_peerconnection.h>
#include <pmx_frame_cryptor.h>

using namespace privmx::endpoint;
using namespace privmx::endpoint::stream;

StreamApiImpl::StreamApiImpl(core::Connection& connection, event::EventApi eventApi) {
    std::shared_ptr<StreamApiLow> apiLow = std::make_shared<StreamApiLow>(StreamApiLow::create(connection, eventApi));
    _api = apiLow;
    auto credentials = _api->getTurnCredentials();
    libwebrtc::LibWebRTC::Initialize();
    _peerConnectionFactory = libwebrtc::LibWebRTC::CreateRTCPeerConnectionFactory();
    _configuration = libwebrtc::RTCConfiguration();
    for(size_t i = 0; i < credentials.size(); i++) {
        PRIVMX_DEBUG("STREAMS", "StreamApiImpl", "IceServer.uri: " + credentials[i].url)
        libwebrtc::IceServer iceServer = {
            .uri=credentials[i].url, 
            .username=portable::string(credentials[i].username), 
            .password=portable::string(credentials[i].password)
        };
        _configuration.ice_servers[i] = iceServer;
    }
    _constraints = libwebrtc::RTCMediaConstraints::Create();
    _frameCryptorOptions = privmx::webrtc::FrameCryptorOptions{.dropFrameIfCryptionFailed=false};
    _webRTC = std::make_shared<WebRTCImpl>( 
        _peerConnectionFactory, 
        _constraints, 
        _configuration,
        [apiLow](const int64_t sessionId, const std::string& candidateAsJson) {
            apiLow->trickle(sessionId, candidateAsJson);
        },
        _frameCryptorOptions
    );
    std:: cout << (_webRTC == nullptr) << std::endl;
}

std::vector<Stream> StreamApiImpl::listStreams(const std::string& streamRoomId) {
    return _api->listStreams(streamRoomId);
}

void StreamApiImpl::joinRoom(const std::string& streamRoomId) {
    std:: cout << (_webRTC == nullptr) << std::endl;
    _api->joinRoom(streamRoomId, _webRTC);
}
void StreamApiImpl::leaveRoom(const std::string& streamRoomId) {
    _api->leaveRoom(streamRoomId);
}
StreamHandle StreamApiImpl::createStream(const std::string& streamRoomId) {
    auto streamHandle = generateNumericId();
    _api->createStream(streamRoomId, streamHandle);
    _streamDataMap.set( 
        streamHandle, 
        std::make_shared<StreamData>(
            privmx::utils::ThreadSaveMap<int64_t, libwebrtc::scoped_refptr<libwebrtc::RTCVideoCapturer>>(),
            StreamStatus::Online,
            streamRoomId
        )
    );
    return streamHandle;
}
std::vector<MediaDevice> StreamApiImpl::getMediaDevices() {
    std::vector<MediaDevice> result;
    std::string name, deviceId;
    name.resize(255);
    deviceId.resize(255);
    // Audio
    libwebrtc::scoped_refptr<libwebrtc::RTCAudioDevice> audioDevice = _peerConnectionFactory->GetAudioDevice();
    uint32_t audio_num = audioDevice->RecordingDevices();
    for (uint32_t i = 0; i < audio_num; ++i) {
        audioDevice->RecordingDeviceName(i, (char*)name.data(), (char*)deviceId.data());
        result.push_back(MediaDevice{name, deviceId, DeviceType::Audio});
    }
    // Video
    libwebrtc::scoped_refptr<libwebrtc::RTCVideoDevice> videoDevice = _peerConnectionFactory->GetVideoDevice();
    uint32_t video_num = videoDevice->NumberOfDevices();
    for (uint32_t i = 0; i < video_num; ++i) {
        videoDevice->GetDeviceName(i, (char*)name.data(), name.size(), (char*)deviceId.data(), deviceId.size());
        result.push_back(MediaDevice{name, deviceId, DeviceType::Video});
    }
    // Desktop
    libwebrtc::scoped_refptr<libwebrtc::RTCDesktopDevice> desktopDevice = _peerConnectionFactory->GetDesktopDevice();
    result.push_back(MediaDevice{"desktop", "desktop", DeviceType::Desktop});
    return result;
}
void StreamApiImpl::addTrack(const StreamHandle& streamHandle, const MediaDevice& track) {
    std::string name, deviceId;
    name.resize(255);
    deviceId.resize(255);

    switch (track.type) {
    case DeviceType::Audio:
        {
            auto streamDataOpt = _streamDataMap.get(streamHandle);
            if(!streamDataOpt.has_value()) {
                throw IncorrectStreamHandleException();
            }
            auto streamData = streamDataOpt.value();
            libwebrtc::scoped_refptr<libwebrtc::RTCAudioDevice> audioDevice = _peerConnectionFactory->GetAudioDevice();
            uint32_t num = audioDevice->RecordingDevices();
            std::optional<uint32_t> id;
            for (uint32_t i = 0; i < num; ++i) {
                audioDevice->RecordingDeviceName(i, (char*)name.data(), (char*)deviceId.data());
                if(name == track.name && deviceId == track.id) {
                    id = i;
                    break;
                }
            }
            if(!id.has_value()) {
                throw IncorrectTrackIdException();
            }
            audioDevice->SetRecordingDevice(id.value());
            auto audioSource = _peerConnectionFactory->CreateAudioSource("audio_source");
            auto audioTrack = _peerConnectionFactory->CreateAudioTrack(audioSource, "audio_track");
            audioTrack->SetVolume(10);
            // Add tracks to the peer connection
            _webRTC->AddAudioTrack(streamData->streamRoomId, audioTrack, std::to_string(id.value()));
        }
        break;
    case DeviceType::Video:
        {
            auto streamDataOpt = _streamDataMap.get(streamHandle);
            if(!streamDataOpt.has_value()) {
                throw IncorrectStreamHandleException();
            }
            auto streamData = streamDataOpt.value();
            libwebrtc::scoped_refptr<libwebrtc::RTCVideoDevice> videoDevice = _peerConnectionFactory->GetVideoDevice();
            uint32_t num = videoDevice->NumberOfDevices();
            std::optional<uint32_t> id;
            for (uint32_t i = 0; i < num; ++i) {
                videoDevice->GetDeviceName(i, (char*)name.data(), name.size(), (char*)deviceId.data(), deviceId.size());
                if(name == track.name && deviceId == track.id) {
                    id = i;
                    break;
                }
            }
            if(!id.has_value()) {
                throw IncorrectTrackIdException();
            }
            libwebrtc::scoped_refptr<libwebrtc::RTCVideoCapturer> videoCapturer = videoDevice->Create("video_capturer", id.value(), 1280, 720, 30);
            libwebrtc::scoped_refptr<libwebrtc::RTCVideoSource> videoSource = _peerConnectionFactory->CreateVideoSource(videoCapturer, "video_source", _constraints);
            libwebrtc::scoped_refptr<libwebrtc::RTCVideoTrack> videoTrack = _peerConnectionFactory->CreateVideoTrack(videoSource, "video_track");
            // Add tracks to the peer connection
            _webRTC->AddVideoTrack(streamData->streamRoomId, videoTrack, std::to_string(id.value()));
            std::lock_guard<std::mutex> lock(streamData->streamMutex);
            streamData->streamCapturers.set(id.value(), videoCapturer);
            if(streamData->status == StreamStatus::Online) {
                videoCapturer->StartCapture();
            }
        }
        break;
    case DeviceType::Desktop:
        {
            throw NotImplementedException();
        }
        break;
    default:
        throw NotImplementedException();
    }
}
void StreamApiImpl::removeTrack(const StreamHandle& streamHandle, const MediaDevice& track) {

}
RemoteStreamId StreamApiImpl::publishStream(const StreamHandle& streamHandle) {
    return _api->publishStream(streamHandle);
}
void StreamApiImpl::unpublishStream(const StreamHandle& streamHandle) {
    _api->unpublishStream(streamHandle);
}
void StreamApiImpl::subscribeToRemoteStream(const std::string& streamRoomId, const RemoteStreamId& streamId, const std::optional<std::vector<RemoteTrackId>>& tracksIds, const StreamSettings& options) {
    _api->subscribeToRemoteStream(streamRoomId, streamId, tracksIds, options.settings);
}
void StreamApiImpl::subscribeToRemoteStreams(const std::string& streamRoomId, std::vector<RemoteStreamId> streamIds, const StreamSettings& options) {
    int64_t streamId = generateNumericId();
    _streamDataMap.set( 
        streamId, 
        std::make_shared<StreamData>(
            privmx::utils::ThreadSaveMap<int64_t, libwebrtc::scoped_refptr<libwebrtc::RTCVideoCapturer>>(),
            StreamStatus::Online,
            streamRoomId
        )
    );
    if(options.OnFrame.has_value()) {
        _webRTC->setOnFrame(streamRoomId, options.OnFrame.value());
    }
    if(options.OnVideoRemove.has_value()) {
        _webRTC->setOnRemoveVideoTrack(streamRoomId, options.OnVideoRemove.value());
    }
    _api->subscribeToRemoteStreams(streamRoomId, streamIds, options.settings);
}
void StreamApiImpl::modifyRemoteStreamSubscription(const std::string& streamRoomId, const RemoteStreamId& streamId, const StreamSettings& options, const std::optional<std::vector<RemoteTrackId>>& tracksIdsToAdd, const std::optional<std::vector<RemoteTrackId>>& tracksIdsToRemove) {
    _api->modifyRemoteStreamSubscription(streamRoomId, streamId, options.settings, tracksIdsToAdd, tracksIdsToRemove);
}
void StreamApiImpl::unsubscribeFromRemoteStream(const std::string& streamRoomId, const RemoteStreamId& streamId) {
    _api->unsubscribeFromRemoteStream(streamRoomId, streamId);
}
void StreamApiImpl::unsubscribeFromRemoteStreams(const std::string& streamRoomId, const std::vector<RemoteStreamId>& streamsIds) {
    _api->unsubscribeFromRemoteStreams(streamRoomId, streamsIds);
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

std::vector<std::string> StreamApiImpl::subscribeFor(const std::vector<std::string>& subscriptionQueries) {
    return _api->subscribeFor(subscriptionQueries);
}

void StreamApiImpl::unsubscribeFrom(const std::vector<std::string>& subscriptionIds) {
    return _api->unsubscribeFrom(subscriptionIds);
}

std::string StreamApiImpl::buildSubscriptionQuery(EventType eventType, EventSelectorType selectorType, const std::string& selectorId) {
    return _api->buildSubscriptionQuery(eventType, selectorType, selectorId);
}

void StreamApiImpl::dropBrokenFrames(const std::string& streamRoomId, bool enable) {
    _frameCryptorOptions = privmx::webrtc::FrameCryptorOptions{.dropFrameIfCryptionFailed=enable};
    _webRTC->setFrameCryptorOptions(streamRoomId, _frameCryptorOptions);
}