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
}

std::vector<StreamInfo> StreamApiImpl::listStreams(const std::string& streamRoomId) {
    return _api->listStreams(streamRoomId);
}

void StreamApiImpl::joinStreamRoom(const std::string& streamRoomId) {
    _api->joinStreamRoom(streamRoomId, _webRTC);
}

void StreamApiImpl::leaveStreamRoom(const std::string& streamRoomId) {
    _api->leaveStreamRoom(streamRoomId);
}

StreamHandle StreamApiImpl::createStream(const std::string& streamRoomId) {
    auto streamHandle = _api->createStream(streamRoomId);
    _streamDataMap.set( 
        streamHandle, 
        std::make_shared<StreamData>(
            privmx::utils::ThreadSaveMap<std::string, std::shared_ptr<StreamAudioTrackInfo>>(),
            privmx::utils::ThreadSaveMap<std::string, std::shared_ptr<StreamVideoTrackInfo>>(),
            StreamStatus::Offline,
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
        result.push_back(MediaDevice{getTrimmedString(name), getTrimmedString(deviceId), DeviceType::Audio});
    }
    // Video
    libwebrtc::scoped_refptr<libwebrtc::RTCVideoDevice> videoDevice = _peerConnectionFactory->GetVideoDevice();
    uint32_t video_num = videoDevice->NumberOfDevices();
    for (uint32_t i = 0; i < video_num; ++i) {
        videoDevice->GetDeviceName(i, (char*)name.data(), name.size(), (char*)deviceId.data(), deviceId.size());
        result.push_back(MediaDevice{getTrimmedString(name), getTrimmedString(deviceId), DeviceType::Video});
    }
    // Desktop
    libwebrtc::scoped_refptr<libwebrtc::RTCDesktopDevice> desktopDevice = _peerConnectionFactory->GetDesktopDevice();
    result.push_back(MediaDevice{"desktop", "desktop", DeviceType::Desktop});
    return result;
}

MediaTrack StreamApiImpl::addTrack(const StreamHandle& streamHandle, const MediaDevice& mediaDevice) {

    auto streamDataOpt = _streamDataMap.get(streamHandle);
    if(!streamDataOpt.has_value()) {
        throw IncorrectStreamHandleException();
    }
    auto streamData = streamDataOpt.value();
    std::string name, deviceId;
    name.resize(255);
    deviceId.resize(255);

    switch (mediaDevice.type) {
    case DeviceType::Audio:
        {;
            libwebrtc::scoped_refptr<libwebrtc::RTCAudioDevice> audioDevice = _peerConnectionFactory->GetAudioDevice();
            uint32_t num = audioDevice->RecordingDevices();
            std::optional<uint32_t> id;
            for (uint32_t i = 0; i < num; ++i) {
                audioDevice->RecordingDeviceName(i, (char*)name.data(), (char*)deviceId.data());
                if(getTrimmedString(name) == mediaDevice.name && getTrimmedString(deviceId) == mediaDevice.id) {
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
            std::lock_guard<std::mutex> lock(streamData->streamMutex);
            streamData->audioTracks.set(
                mediaDevice.name + "-" + mediaDevice.id, 
                std::make_shared<StreamAudioTrackInfo>(audioDevice, mediaDevice.name, mediaDevice.id, audioSource, audioTrack, TrackStatus::ToAdd)
            );
            return MediaTrack{[audioTrack](bool enabled) {
                audioTrack->set_enabled(enabled);
            }};
        }
        break;
    case DeviceType::Video:
        {
            libwebrtc::scoped_refptr<libwebrtc::RTCVideoDevice> videoDevice = _peerConnectionFactory->GetVideoDevice();
            uint32_t num = videoDevice->NumberOfDevices();
            std::optional<uint32_t> id;
            for (uint32_t i = 0; i < num; ++i) {
                videoDevice->GetDeviceName(i, (char*)name.data(), name.size(), (char*)deviceId.data(), deviceId.size());
                if(getTrimmedString(name) == mediaDevice.name && getTrimmedString(deviceId) == mediaDevice.id) {
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
            std::lock_guard<std::mutex> lock(streamData->streamMutex);
            streamData->videoTracks.set(
                mediaDevice.name + "-" + mediaDevice.id, 
                std::make_shared<StreamVideoTrackInfo>(videoDevice, mediaDevice.name, mediaDevice.id, videoCapturer, videoSource, videoTrack, TrackStatus::ToAdd)
            );
            return MediaTrack{[videoTrack](bool enabled) {
                videoTrack->set_enabled(enabled);
            }};
        }
        break;
    case DeviceType::Desktop:
        {
            auto streamDataOpt = _streamDataMap.get(streamHandle);
            if(!streamDataOpt.has_value()) {
                throw IncorrectStreamHandleException();
            }
            auto streamData = streamDataOpt.value();
            libwebrtc::scoped_refptr<libwebrtc::RTCDesktopDevice> desktopDevice = _peerConnectionFactory->GetDesktopDevice();
            auto desktopMediaList = desktopDevice->GetDesktopMediaList(libwebrtc::DesktopType::kScreen);
            desktopMediaList->UpdateSourceList(true, true);
            libwebrtc::scoped_refptr<libwebrtc::RTCDesktopCapturer> desktopCapturer = desktopDevice->CreateDesktopCapturer(desktopMediaList->GetSource(0));
            libwebrtc::scoped_refptr<libwebrtc::RTCVideoSource> videoSource = _peerConnectionFactory->CreateDesktopSource(desktopCapturer, "desktop_source", _constraints);
            libwebrtc::scoped_refptr<libwebrtc::RTCVideoTrack> videoTrack = _peerConnectionFactory->CreateVideoTrack(videoSource, "desktop_track");
            std::lock_guard<std::mutex> lock(streamData->streamMutex);
            streamData->desktopTracks.set(
                mediaDevice.name + "-" + mediaDevice.id, 
                std::make_shared<StreamDesktopTrackInfo>(desktopDevice, mediaDevice.name, mediaDevice.id, desktopCapturer, videoSource, videoTrack, TrackStatus::ToAdd)
            );
            return MediaTrack{[videoTrack](bool enabled) {
                videoTrack->set_enabled(enabled);
            }};
        }
        break;
    default:
        throw NotImplementedException();
    }
}

void StreamApiImpl::removeTrack(const StreamHandle& streamHandle, const MediaDevice& mediaDevice) {
    
    auto streamDataOpt = _streamDataMap.get(streamHandle);
    if(!streamDataOpt.has_value()) {
        throw IncorrectStreamHandleException();
    }
    auto streamData = streamDataOpt.value();

    switch (mediaDevice.type) {
    case DeviceType::Audio:
        {            
            LOG_INFO("StreamApiImpl::removeTrack Audio - ", mediaDevice.name + "-" + mediaDevice.id)
            std::lock_guard<std::mutex> lock(streamData->streamMutex);
            auto trackOpt = streamData->audioTracks.get(mediaDevice.name + "-" + mediaDevice.id);
            if(!trackOpt.has_value()) {
                throw IncorrectTrackIdException();
            }
            auto track = trackOpt.value();
            if(track->status == TrackStatus::ToAdd) {
                streamData->audioTracks.erase(mediaDevice.name + "-" + mediaDevice.id);
            } else if(track->status == TrackStatus::Published) {
                track->status = TrackStatus::ToRemove;
                streamData->audioTracks.set(mediaDevice.name + "-" + mediaDevice.id, track);
            }
        }
        break;
    case DeviceType::Video:
        {
            
            LOG_INFO("StreamApiImpl::removeTrack Video - ", mediaDevice.name + "-" + mediaDevice.id)
            std::lock_guard<std::mutex> lock(streamData->streamMutex);
            auto trackOpt = streamData->videoTracks.get(mediaDevice.name + "-" + mediaDevice.id);
            if(!trackOpt.has_value()) {
                throw IncorrectTrackIdException();
            }
            auto track = trackOpt.value();
            if(track->status == TrackStatus::ToAdd) {
                streamData->videoTracks.erase(mediaDevice.name + "-" + mediaDevice.id);
            } else if(track->status == TrackStatus::Published) {
                track->status = TrackStatus::ToRemove;
                streamData->videoTracks.set(mediaDevice.name + "-" + mediaDevice.id, track);
            }
        }
        break;
    case DeviceType::Desktop:
        {
            LOG_INFO("StreamApiImpl::removeTrack Desktop - ", mediaDevice.name + "-" + mediaDevice.id)
            std::lock_guard<std::mutex> lock(streamData->streamMutex);
            auto trackOpt = streamData->desktopTracks.get(mediaDevice.name + "-" + mediaDevice.id);
            if(!trackOpt.has_value()) {
                throw IncorrectTrackIdException();
            }
            auto track = trackOpt.value();
            if(track->status == TrackStatus::ToAdd) {
                streamData->desktopTracks.erase(mediaDevice.name + "-" + mediaDevice.id);
            } else if(track->status == TrackStatus::Published) {
                track->status = TrackStatus::ToRemove;
                streamData->desktopTracks.set(mediaDevice.name + "-" + mediaDevice.id, track);
            }
        }
        break;
    default:
        throw NotImplementedException();
    }
}

StreamPublishResult StreamApiImpl::publishStream(const StreamHandle& streamHandle) {
    auto streamDataOpt = _streamDataMap.get(streamHandle);
    if(!streamDataOpt.has_value()) {
        throw IncorrectStreamHandleException();
    }
    auto streamData = streamDataOpt.value();
    // Add tracks to the peer connection
    std::vector<std::pair<std::string, libwebrtc::scoped_refptr<libwebrtc::RTCAudioTrack>>> audioTracksToAdd;
    std::vector<std::pair<std::string, libwebrtc::scoped_refptr<libwebrtc::RTCVideoTrack>>> videoTracksToAdd;
    streamData->audioTracks.forAll([&](const std::string& id,const std::shared_ptr<StreamAudioTrackInfo>& audio) {
        if(audio->status == TrackStatus::ToAdd) {
            audio->status = TrackStatus::Published;
            audioTracksToAdd.push_back({id, audio->track});
        }
    });
    streamData->videoTracks.forAll([&](const std::string& id,const std::shared_ptr<StreamVideoTrackInfo>& video) {
        if(video->status == TrackStatus::ToAdd) {
            video->status = TrackStatus::Published;
            if(!video->capturer->CaptureStarted()) {
                video->capturer->StartCapture();
            }
            videoTracksToAdd.push_back({id, video->track});
        }
    });
    streamData->desktopTracks.forAll([&](const std::string& id,const std::shared_ptr<StreamDesktopTrackInfo>& desktop) {
        if(desktop->status == TrackStatus::ToAdd) {
            desktop->status = TrackStatus::Published;
            if(!desktop->capturer->IsRunning()) {
                desktop->capturer->Start(15);
            }
            videoTracksToAdd.push_back({id, desktop->track});
        }
    });
    streamData->status = Online;
    _webRTC->createPeerConnectionWithLocalStream(streamData->streamRoomId, audioTracksToAdd, videoTracksToAdd);
    return _api->publishStream(streamHandle);
}

StreamPublishResult StreamApiImpl::updateStream(const StreamHandle& streamHandle) {
     auto streamDataOpt = _streamDataMap.get(streamHandle);
    if(!streamDataOpt.has_value()) {
        throw IncorrectStreamHandleException();
    }
    auto streamData = streamDataOpt.value();

    // Add tracks to the peer connection
    // UPDATE audio tracks
    std::vector<std::pair<std::string, libwebrtc::scoped_refptr<libwebrtc::RTCAudioTrack>>> audioTracksToAdd;
    std::vector<std::pair<std::string, libwebrtc::scoped_refptr<libwebrtc::RTCAudioTrack>>> audioTracksToRemove;
    streamData->audioTracks.forAll([&](const std::string& id,const std::shared_ptr<StreamAudioTrackInfo>& audio) {
        if(audio->status == TrackStatus::ToAdd) {
            audio->status = TrackStatus::Published;
            audioTracksToAdd.push_back({id, audio->track});
        } else if(audio->status == TrackStatus::ToRemove) {
            audioTracksToRemove.push_back({id, audio->track});
        }
    });
    for(const auto& toRemove : audioTracksToRemove) {
        streamData->audioTracks.erase(toRemove.first);
    }
    // UPDATE video tracks
    std::vector<std::pair<std::string, libwebrtc::scoped_refptr<libwebrtc::RTCVideoTrack>>> videoTracksToAdd;
    std::vector<std::pair<std::string, libwebrtc::scoped_refptr<libwebrtc::RTCVideoTrack>>> videoTracksToRemove;
    streamData->videoTracks.forAll([&](const std::string& id,const std::shared_ptr<StreamVideoTrackInfo>& video) {
        if(video->status == TrackStatus::ToAdd) {
            if(!video->capturer->CaptureStarted()) video->capturer->StartCapture();
            video->status = TrackStatus::Published;
            videoTracksToAdd.push_back({id, video->track});
        } else if(video->status == TrackStatus::ToRemove) {
            if(video->capturer->CaptureStarted()) video->capturer->StopCapture();
            videoTracksToRemove.push_back({id, video->track});
        }
    });
    size_t toRemove = 0;
    for(; toRemove < videoTracksToRemove.size(); toRemove++ ) {
        streamData->videoTracks.erase(videoTracksToRemove[toRemove].first);
    }
    streamData->desktopTracks.forAll([&](const std::string& id,const std::shared_ptr<StreamDesktopTrackInfo>& desktop) {
        if(desktop->status == TrackStatus::ToAdd) {
            if(!desktop->capturer->IsRunning()) desktop->capturer->Start(15);
            desktop->status = TrackStatus::Published;
            videoTracksToAdd.push_back({id, desktop->track});
        } else if(desktop->status == TrackStatus::ToRemove) {
            if(desktop->capturer->IsRunning()) desktop->capturer->Stop();
            videoTracksToRemove.push_back({id, desktop->track});
        }
    });
    for(; toRemove < videoTracksToRemove.size(); toRemove++ ) {
        streamData->desktopTracks.erase(videoTracksToRemove[toRemove].first);
    }
    _webRTC->updatePeerConnectionWithLocalStream(streamData->streamRoomId, audioTracksToAdd, videoTracksToAdd, audioTracksToRemove, videoTracksToRemove);
    return _api->updateStream(streamHandle);
}

void StreamApiImpl::unpublishStream(const StreamHandle& streamHandle) {
    _api->unpublishStream(streamHandle);
}

void StreamApiImpl::subscribeToRemoteStreams(const std::string& streamRoomId, const std::vector<StreamSubscription>& subscriptions, const StreamSettings& options) {
    int64_t streamId = generateNumericId();
    _streamDataMap.set( 
        streamId, 
        std::make_shared<StreamData>(
            privmx::utils::ThreadSaveMap<std::string, std::shared_ptr<StreamAudioTrackInfo>>(),
            privmx::utils::ThreadSaveMap<std::string, std::shared_ptr<StreamVideoTrackInfo>>(),
            StreamStatus::Offline,
            streamRoomId
        )
    );
    _api->subscribeToRemoteStreams(streamRoomId, subscriptions, options.settings);
}

void StreamApiImpl::modifyRemoteStreamsSubscriptions(const std::string& streamRoomId, const std::vector<StreamSubscription>& subscriptionsToAdd, const std::vector<StreamSubscription>& subscriptionsToRemove, const StreamSettings& options) {
    _api->modifyRemoteStreamsSubscriptions(streamRoomId, subscriptionsToAdd, subscriptionsToRemove, options.settings);
}

void StreamApiImpl::unsubscribeFromRemoteStreams(const std::string& streamRoomId, const std::vector<StreamSubscription>& subscriptionsToRemove) {
    _api->unsubscribeFromRemoteStreams(streamRoomId, subscriptionsToRemove);
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

void StreamApiImpl::setOnTrackInterface(std::shared_ptr<OnTrackInterface> onTrackInterface) {
    _webRTC->setOnTrackInterface(onTrackInterface);
}