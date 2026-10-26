/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/EndpointUtils.hpp>
#include <privmx/endpoint/core/EventVarSerializer.hpp>
#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/endpoint/core/JsonSerializer.hpp>

#include <privmx/endpoint/core/EventBuilder.hpp>

#include "privmx/endpoint/stream/StreamApiImpl.hpp"
#include "privmx/endpoint/stream/StreamApiLow.hpp"
#include "privmx/endpoint/stream/StreamException.hpp"
#include "privmx/endpoint/stream/webrtc/Events.hpp"
#include <privmx/endpoint/core/CoreException.hpp>

#include <base/portable.h>
#include <libwebrtc.h>
#include <pmx_frame_cryptor.h>
#include <rtc_audio_device.h>
#include <rtc_peerconnection.h>

using namespace privmx::endpoint;
using namespace privmx::endpoint::stream;

StreamApiImpl::StreamApiImpl(core::Connection& connection) {
    std::shared_ptr<StreamApiLow> apiLow = std::make_shared<StreamApiLow>(StreamApiLow::create(connection));
    _api = apiLow;
    _eventMiddleware = connection.getImpl()->getEventMiddleware();
    _connectionStateTracker = std::make_shared<ConnectionStateTracker>(
        [this](const std::string& streamRoomId, StreamConnectionState state) {
            emitConnectionStateChangedEvent(streamRoomId, state);
        },
        [this](const std::string& streamRoomId, const std::string& connectionType) {
            return recoverConnection(streamRoomId, connectionType);
        }
    );
    auto credentials = _api->getTurnCredentials();
    libwebrtc::LibWebRTC::Initialize();
    _peerConnectionFactory = libwebrtc::LibWebRTC::CreateRTCPeerConnectionFactory();
    _configuration = libwebrtc::RTCConfiguration();
    for (size_t i = 0; i < credentials.size(); i++) {
        LOG_TRACE("StreamApiImpl - IceServer.uri: " + credentials[i].url)
        libwebrtc::IceServer iceServer = {
            .uri = credentials[i].url,
            .username = portable::string(credentials[i].username),
            .password = portable::string(credentials[i].password)
        };
        _configuration.ice_servers[i] = iceServer;
    }
    _constraints = libwebrtc::RTCMediaConstraints::Create();
    _frameCryptorOptions = privmx::webrtc::FrameCryptorOptions{.dropFrameIfCryptionFailed = false};
    std::weak_ptr<ConnectionStateTracker> tracker = _connectionStateTracker;
    _webRTC = std::make_shared<WebRTCImpl>(
        _peerConnectionFactory, _constraints, _configuration,
        [apiLow](const int64_t sessionId, const std::string& candidateAsJson) {
            apiLow->trickle(sessionId, candidateAsJson);
        },
        [tracker](const std::string& streamRoomId, const std::string& connectionType, PeerConnectionState state) {
            if (auto alive = tracker.lock()) {
                alive->setConnectionState(streamRoomId, connectionType, state);
            }
        },
        [this](const std::string& streamRoomId, const std::vector<std::string>& streamIds) {
            markStreamsAsStale(streamRoomId, streamIds);
        },
        _frameCryptorOptions, _api
    );
    _eventMiddleware = connection.getImpl()->getEventMiddleware();
    _disconnectedListenerId = _eventMiddleware->addDisconnectedEventListener(
        std::bind(&StreamApiImpl::processDisconnectedEvent, this)
    );
}

StreamApiImpl::~StreamApiImpl() {
    _eventMiddleware->removeDisconnectedEventListener(_disconnectedListenerId);
    // joins the tracker's thread first, so no recovery runs while the layers it reaches are torn down
    _connectionStateTracker.reset();
    _streamDataMap.clear();
    _webRTC.reset();
    _api.reset();
    libwebrtc::LibWebRTC::Terminate();
}

std::vector<StreamInfo> StreamApiImpl::listStreams(const std::string& streamRoomId) {
    return _api->listStreams(streamRoomId);
}

std::vector<StreamSubscriber> StreamApiImpl::listStreamRoomParticipants(const std::string& streamRoomId) {
    return _api->listStreamRoomParticipants(streamRoomId);
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
            privmx::utils::ThreadSaveMap<std::string, std::shared_ptr<StreamVideoTrackInfo>>(), StreamStatus::Offline,
            streamRoomId
        )
    );
    return streamHandle;
}

std::vector<AudioDevice> StreamApiImpl::getAudioDevices() {
    std::vector<AudioDevice> result;
    std::string name, deviceId;
    name.resize(255);
    deviceId.resize(255);
    // Audio
    libwebrtc::scoped_refptr<libwebrtc::RTCAudioDevice> audioDevice = _peerConnectionFactory->GetAudioDevice();
    uint32_t audio_num = audioDevice->RecordingDevices();
    for (uint32_t i = 0; i < audio_num; ++i) {
        audioDevice->RecordingDeviceName(i, (char*)name.data(), (char*)deviceId.data());
        result.push_back(AudioDevice{getTrimmedString(name), getTrimmedString(deviceId), DeviceType::Audio});
    }
    return result;
}
std::vector<VideoDevice> StreamApiImpl::getVideoDevices() {
    std::vector<VideoDevice> result;
    std::string name, deviceId;
    name.resize(255);
    deviceId.resize(255);
    // Video
    libwebrtc::scoped_refptr<libwebrtc::RTCVideoDevice> videoDevice = _peerConnectionFactory->GetVideoDevice();
    uint32_t video_num = videoDevice->NumberOfDevices();
    for (uint32_t i = 0; i < video_num; ++i) {
        videoDevice->GetDeviceName(i, (char*)name.data(), name.size(), (char*)deviceId.data(), deviceId.size());
        result.push_back(VideoDevice{getTrimmedString(name), getTrimmedString(deviceId), DeviceType::Video});
    }
    return result;
}
std::vector<DesktopDevice> StreamApiImpl::getDesktopDevices(DesktopType desktopType) {
    std::vector<DesktopDevice> result;
    std::string name, deviceId;
    name.resize(255);
    deviceId.resize(255);
    // Desktop
    libwebrtc::scoped_refptr<libwebrtc::RTCDesktopDevice> desktopDevice = _peerConnectionFactory->GetDesktopDevice();
    libwebrtc::scoped_refptr<libwebrtc::RTCDesktopMediaList> desktopMediaList;
    if (desktopType == DesktopType::Screen) {
        desktopMediaList = desktopDevice->GetDesktopMediaList(libwebrtc::DesktopType::kScreen);
    } else if (desktopType == DesktopType::Window) {
        desktopMediaList = desktopDevice->GetDesktopMediaList(libwebrtc::DesktopType::kWindow);
    }
    desktopMediaList->UpdateSourceList(true, true);
    for (int i = 0; i < desktopMediaList->GetSourceCount(); ++i) {
        desktopMediaList->GetThumbnail(desktopMediaList->GetSource(i));
        auto thumbnail = desktopMediaList->GetSource(i)->thumbnail();
        auto deviceType = DeviceType::Desktop_Screen;
        auto deviceName = "Desktop_Screen" + std::to_string(i + 1);
        if (desktopType == DesktopType::Window) {
            deviceType = DeviceType::Desktop_Window;
            deviceName = "Desktop_Screen" + std::to_string(i + 1);
        }
        result.push_back(DesktopDevice{deviceName, std::to_string(i + 1), deviceType, thumbnail.std_vector()});
    }
    return result;
}

MediaTrack StreamApiImpl::addFakeVideoTrack(const StreamHandle& streamHandle) {
    auto streamDataOpt = _streamDataMap.get(streamHandle);
    if (!streamDataOpt.has_value()) {
        throw IncorrectStreamHandleException();
    }
    auto streamData = streamDataOpt.value();
    std::string name, deviceId;
    name.resize(255);
    deviceId.resize(255);
    libwebrtc::scoped_refptr<libwebrtc::RTCVideoCapturer> videoCapturer;
    libwebrtc::scoped_refptr<libwebrtc::RTCVideoSource> videoSource;
    libwebrtc::scoped_refptr<libwebrtc::RTCVideoDevice> videoDevice;

    videoSource = _peerConnectionFactory->CreateFakeVideoSource();
    libwebrtc::scoped_refptr<libwebrtc::RTCVideoTrack> videoTrack = _peerConnectionFactory->CreateVideoTrack(
        videoSource, "video_track"
    );
    std::lock_guard<std::mutex> lock(streamData->streamMutex);
    streamData->videoTracks.set(
        "FAKE-FAKE",
        std::make_shared<StreamVideoTrackInfo>(
            videoDevice, "FAKE", "FAKE", videoCapturer, videoSource, videoTrack, TrackStatus::ToAdd
        )
    );
    return MediaTrack{[videoTrack](bool enabled) { videoTrack->set_enabled(enabled); }};
}

MediaTrack StreamApiImpl::addTrack(
    const StreamHandle& streamHandle,
    const MediaDevice& mediaDevice,
    const MediaTrackConstrains& mediaTrackConstrains
) {
    auto streamDataOpt = _streamDataMap.get(streamHandle);
    if (!streamDataOpt.has_value()) {
        throw IncorrectStreamHandleException();
    }
    auto streamData = streamDataOpt.value();
    std::string name, deviceId;
    name.resize(255);
    deviceId.resize(255);

    switch (mediaDevice.type) {
    case DeviceType::Audio: {
        ;
        libwebrtc::scoped_refptr<libwebrtc::RTCAudioDevice> audioDevice = _peerConnectionFactory->GetAudioDevice();
        uint32_t num = audioDevice->RecordingDevices();
        std::optional<uint32_t> id;
        for (uint32_t i = 0; i < num; ++i) {
            audioDevice->RecordingDeviceName(i, (char*)name.data(), (char*)deviceId.data());
            if (getTrimmedString(name) == mediaDevice.name && getTrimmedString(deviceId) == mediaDevice.id) {
                id = i;
                break;
            }
        }
        if (!id.has_value()) {
            throw IncorrectTrackIdException();
        }
        audioDevice->SetRecordingDevice(id.value());
        auto audioSource = _peerConnectionFactory->CreateAudioSource("audio_source");
        auto audioTrack = _peerConnectionFactory->CreateAudioTrack(audioSource, "audio_track");
        std::lock_guard<std::mutex> lock(streamData->streamMutex);
        streamData->audioTracks.set(
            mediaDevice.name + "-" + mediaDevice.id,
            std::make_shared<StreamAudioTrackInfo>(
                audioDevice, mediaDevice.name, mediaDevice.id, audioSource, audioTrack, TrackStatus::ToAdd
            )
        );
        return MediaTrack{[audioTrack](bool enabled) { audioTrack->set_enabled(enabled); }};
    } break;
    case DeviceType::Video: {
        libwebrtc::scoped_refptr<libwebrtc::RTCVideoCapturer> videoCapturer;
        libwebrtc::scoped_refptr<libwebrtc::RTCVideoSource> videoSource;
        libwebrtc::scoped_refptr<libwebrtc::RTCVideoDevice> videoDevice = _peerConnectionFactory->GetVideoDevice();
        uint32_t num = videoDevice->NumberOfDevices();
        std::optional<uint32_t> id;
        for (uint32_t i = 0; i < num; ++i) {
            videoDevice->GetDeviceName(i, (char*)name.data(), name.size(), (char*)deviceId.data(), deviceId.size());
            if (getTrimmedString(name) == mediaDevice.name && getTrimmedString(deviceId) == mediaDevice.id) {
                id = i;
                break;
            }
        }
        if (!id.has_value()) {
            throw IncorrectTrackIdException();
        }
        // the device is captured again below, so the capturer holding it is released first
        stopCapturerOfReplacedTrack(streamData, mediaDevice.name + "-" + mediaDevice.id);
        videoCapturer = videoDevice->Create(
            "video_capturer", id.value(), mediaTrackConstrains.idealWidth, mediaTrackConstrains.idealHeight,
            mediaTrackConstrains.idealFps
        );
        videoSource = _peerConnectionFactory->CreateVideoSource(videoCapturer, "video_source", _constraints);

        libwebrtc::scoped_refptr<libwebrtc::RTCVideoTrack> videoTrack = _peerConnectionFactory->CreateVideoTrack(
            videoSource, "video_track"
        );
        std::lock_guard<std::mutex> lock(streamData->streamMutex);
        streamData->videoTracks.set(
            mediaDevice.name + "-" + mediaDevice.id,
            std::make_shared<StreamVideoTrackInfo>(
                videoDevice, mediaDevice.name, mediaDevice.id, videoCapturer, videoSource, videoTrack,
                TrackStatus::ToAdd
            )
        );
        return MediaTrack{[videoTrack](bool enabled) { videoTrack->set_enabled(enabled); }};
    } break;
    case DeviceType::Desktop_Screen:
    case DeviceType::Desktop_Window: {
        auto streamDataOpt = _streamDataMap.get(streamHandle);
        if (!streamDataOpt.has_value()) {
            throw IncorrectStreamHandleException();
        }
        auto streamData = streamDataOpt.value();
        libwebrtc::scoped_refptr<libwebrtc::RTCDesktopDevice> desktopDevice = _peerConnectionFactory->GetDesktopDevice(
        );
        libwebrtc::scoped_refptr<libwebrtc::RTCDesktopMediaList> desktopMediaList;
        if (mediaDevice.type == DeviceType::Desktop_Screen) {
            desktopMediaList = desktopDevice->GetDesktopMediaList(libwebrtc::DesktopType::kScreen);
        } else if (mediaDevice.type == DeviceType::Desktop_Window) {
            desktopMediaList = desktopDevice->GetDesktopMediaList(libwebrtc::DesktopType::kWindow);
        }
        desktopMediaList->UpdateSourceList(true, true);
        int id = std::stol(mediaDevice.id) - 1;
        if (id >= desktopMediaList->GetSourceCount()) {
            throw IncorrectTrackIdException();
        }
        // the source is captured again below, so the capturer holding it is released first
        stopCapturerOfReplacedTrack(streamData, mediaDevice.name + "-" + mediaDevice.id);
        libwebrtc::scoped_refptr<libwebrtc::RTCDesktopCapturer> desktopCapturer = desktopDevice->CreateDesktopCapturer(
            desktopMediaList->GetSource(id)
        );
        libwebrtc::scoped_refptr<libwebrtc::RTCVideoSource> videoSource = _peerConnectionFactory->CreateDesktopSource(
            desktopCapturer, "desktop_source", _constraints
        );
        libwebrtc::scoped_refptr<libwebrtc::RTCVideoTrack> videoTrack = _peerConnectionFactory->CreateVideoTrack(
            videoSource, "desktop_track"
        );
        std::lock_guard<std::mutex> lock(streamData->streamMutex);
        streamData->desktopTracks.set(
            mediaDevice.name + "-" + mediaDevice.id,
            std::make_shared<StreamDesktopTrackInfo>(
                desktopDevice, mediaDevice.name, mediaDevice.id, desktopCapturer, videoSource, videoTrack,
                TrackStatus::ToAdd, mediaTrackConstrains.idealFps
            )
        );
        return MediaTrack{[videoTrack](bool enabled) { videoTrack->set_enabled(enabled); }};
    }

    case DeviceType::Plain: {
        auto streamDataOpt = _streamDataMap.get(streamHandle);
        if (!streamDataOpt.has_value()) {
            throw IncorrectStreamHandleException();
        }
        auto streamData = streamDataOpt.value();
        std::lock_guard<std::mutex> lock(streamData->streamMutex);
        if (streamData->dataTrack && streamData->dataTrack->status != TrackStatus::ToRemove) {
            throw ThereCanBeOnlyOneDataTrackException();
        }
        if (streamData->dataTrack) {
            // the data track staged for removal is still in the connection, so adding it again cancels that
            streamData->dataTrack->status = TrackStatus::Published;
            return MediaTrack{[]([[maybe_unused]] bool enabled) { return; }};
        }
        auto streamDataTrackInfo = std::make_shared<StreamDataTrackInfo>(
            TrackStatus::ToAdd, []([[maybe_unused]] std::string data) { return; }
        );

        streamData->dataTrack = streamDataTrackInfo;
        return MediaTrack{[]([[maybe_unused]] bool enabled) { return; }};
    }
    default:
        throw core::NotImplementedException();
    }
}

void StreamApiImpl::removeTrack(const StreamHandle& streamHandle, const MediaDevice& mediaDevice) {

    auto streamDataOpt = _streamDataMap.get(streamHandle);
    if (!streamDataOpt.has_value()) {
        throw IncorrectStreamHandleException();
    }
    auto streamData = streamDataOpt.value();

    switch (mediaDevice.type) {
    case DeviceType::Audio: {
        LOG_INFO("StreamApiImpl::removeTrack Audio - ", mediaDevice.name + "-" + mediaDevice.id)
        std::lock_guard<std::mutex> lock(streamData->streamMutex);
        auto trackOpt = streamData->audioTracks.get(mediaDevice.name + "-" + mediaDevice.id);
        if (!trackOpt.has_value()) {
            throw IncorrectTrackIdException();
        }
        auto track = trackOpt.value();
        if (track->status == TrackStatus::ToAdd) {
            streamData->audioTracks.erase(mediaDevice.name + "-" + mediaDevice.id);
        } else if (track->status == TrackStatus::Published) {
            track->status = TrackStatus::ToRemove;
        }
    } break;
    case DeviceType::Video: {
        LOG_INFO("StreamApiImpl::removeTrack Video - ", mediaDevice.name + "-" + mediaDevice.id)
        std::lock_guard<std::mutex> lock(streamData->streamMutex);
        auto trackOpt = streamData->videoTracks.get(mediaDevice.name + "-" + mediaDevice.id);
        if (!trackOpt.has_value()) {
            throw IncorrectTrackIdException();
        }
        auto track = trackOpt.value();
        if (track->status == TrackStatus::ToAdd) {
            streamData->videoTracks.erase(mediaDevice.name + "-" + mediaDevice.id);
        } else if (track->status == TrackStatus::Published) {
            track->status = TrackStatus::ToRemove;
        }
    } break;
    case DeviceType::Desktop_Screen:
    case DeviceType::Desktop_Window: {
        LOG_INFO("StreamApiImpl::removeTrack Desktop - ", mediaDevice.name + "-" + mediaDevice.id)
        std::lock_guard<std::mutex> lock(streamData->streamMutex);
        auto trackOpt = streamData->desktopTracks.get(mediaDevice.name + "-" + mediaDevice.id);
        if (!trackOpt.has_value()) {
            throw IncorrectTrackIdException();
        }
        auto track = trackOpt.value();
        if (track->status == TrackStatus::ToAdd) {
            streamData->desktopTracks.erase(mediaDevice.name + "-" + mediaDevice.id);
        } else if (track->status == TrackStatus::Published) {
            track->status = TrackStatus::ToRemove;
        }
    } break;
    case DeviceType::Plain: {
        LOG_INFO("StreamApiImpl::removeTrack Plain - ", mediaDevice.name + "-" + mediaDevice.id)
        std::lock_guard<std::mutex> lock(streamData->streamMutex);

        auto track = streamData->dataTrack;
        if (!track) {
            throw IncorrectTrackIdException();
        }
        if (track->status == TrackStatus::ToAdd) {
            streamData->dataTrack = nullptr;
        } else if (track->status == TrackStatus::Published) {
            track->status = TrackStatus::ToRemove;
        }
    } break;
    default:
        throw core::NotImplementedException();
    }
}

StreamPublishResult StreamApiImpl::publishStream(const StreamHandle& streamHandle) {
    auto streamData = getStreamData(streamHandle);
    if (streamData->status == Online) {
        throw StreamAlreadyPublishedException();
    }
    std::lock_guard<std::mutex> lock(streamData->streamMutex);
    StreamTracksUpdate update = collectTracksUpdate(streamData);
    _webRTC->createPeerConnectionWithLocalStream(
        streamData->streamRoomId, update.audioTracksToAdd,
        joinVideoTracks(update.videoTracksToAdd, update.desktopTracksToAdd), update.dataChannel
    );
    StreamPublishResult result{};
    try {
        result = _api->publishStream(streamHandle);
    } catch (...) {
        // nothing was published, so the connection built for it is dropped and the tracks stay staged for a retry
        try {
            _webRTC->close(streamData->streamRoomId, "publisher");
        } catch (...) {
            LOG_ERROR("StreamApiImpl::publishStream", "closing the connection of a failed publication failed")
        }
        throw;
    }
    applyTracksUpdate(streamData, update);
    streamData->status = Online;
    return result;
}

StreamPublishResult StreamApiImpl::updateStream(const StreamHandle& streamHandle) {
    auto streamData = getStreamData(streamHandle);
    if (streamData->status != Online) {
        throw StreamHandleNotPublishedException();
    }
    std::lock_guard<std::mutex> lock(streamData->streamMutex);
    StreamTracksUpdate update = collectTracksUpdate(streamData);
    sendTracksUpdateToPeerConnection(streamData->streamRoomId, update);
    StreamPublishResult result{};
    try {
        result = _api->updateStream(streamHandle);
    } catch (...) {
        // the other participants never learned about the staged tracks, so they must not reach them with
        // the next update either - the connection goes back to what the Stream was published with
        try {
            revertTracksUpdateOnPeerConnection(streamData->streamRoomId, update);
        } catch (...) {
            LOG_ERROR("StreamApiImpl::updateStream", "reverting the connection after a failed update failed")
        }
        throw;
    }
    applyTracksUpdate(streamData, update);
    return result;
}

void StreamApiImpl::stopCapturerOfReplacedTrack(
    const std::shared_ptr<StreamData>& streamData,
    const std::string& trackId
) {
    auto videoTrack = streamData->videoTracks.get(trackId);
    if (videoTrack.has_value() &&
        videoTrack.value()->capturer.get() != NULL &&
        videoTrack.value()->capturer->CaptureStarted()) {
        videoTrack.value()->capturer->StopCapture();
    }
    auto desktopTrack = streamData->desktopTracks.get(trackId);
    if (desktopTrack.has_value() && desktopTrack.value()->capturer->IsRunning()) {
        desktopTrack.value()->capturer->Stop();
    }
}

std::shared_ptr<StreamApiImpl::StreamData> StreamApiImpl::getStreamData(const StreamHandle& streamHandle) {
    auto streamDataOpt = _streamDataMap.get(streamHandle);
    if (!streamDataOpt.has_value()) {
        throw IncorrectStreamHandleException();
    }
    return streamDataOpt.value();
}

StreamApiImpl::StreamTracksUpdate StreamApiImpl::collectTracksUpdate(const std::shared_ptr<StreamData>& streamData) {
    StreamTracksUpdate update;
    streamData->audioTracks.forAll([&](const std::string& id, const std::shared_ptr<StreamAudioTrackInfo>& audio) {
        if (audio->status == TrackStatus::ToAdd) {
            update.audioTracksToAdd.push_back({id, audio->track});
        } else if (audio->status == TrackStatus::ToRemove) {
            update.audioTracksToRemove.push_back({id, audio->track});
        }
    });
    streamData->videoTracks.forAll([&](const std::string& id, const std::shared_ptr<StreamVideoTrackInfo>& video) {
        if (video->status == TrackStatus::ToAdd) {
            update.videoTracksToAdd.push_back({id, video->track});
        } else if (video->status == TrackStatus::ToRemove) {
            update.videoTracksToRemove.push_back({id, video->track});
        }
    });
    streamData->desktopTracks.forAll([&](const std::string& id,
                                         const std::shared_ptr<StreamDesktopTrackInfo>& desktop) {
        if (desktop->status == TrackStatus::ToAdd) {
            update.desktopTracksToAdd.push_back({id, desktop->track});
        } else if (desktop->status == TrackStatus::ToRemove) {
            update.desktopTracksToRemove.push_back({id, desktop->track});
        }
    });
    if (streamData->dataTrack) {
        auto dataTrack = streamData->dataTrack;
        if (dataTrack->status != TrackStatus::ToRemove) {
            update.dataChannel = std::make_pair(dataTrack->label, &dataTrack->sendData);
        }
        if (dataTrack->status != TrackStatus::ToAdd) {
            update.dataChannelBeforeUpdate = std::make_pair(dataTrack->label, &dataTrack->sendData);
        }
    }
    return update;
}

void StreamApiImpl::sendTracksUpdateToPeerConnection(
    const std::string& streamRoomId,
    const StreamTracksUpdate& update
) {
    _webRTC->updatePeerConnectionWithLocalStream(
        streamRoomId, update.audioTracksToAdd, joinVideoTracks(update.videoTracksToAdd, update.desktopTracksToAdd),
        update.audioTracksToRemove, joinVideoTracks(update.videoTracksToRemove, update.desktopTracksToRemove),
        update.dataChannel
    );
}

void StreamApiImpl::revertTracksUpdateOnPeerConnection(
    const std::string& streamRoomId,
    const StreamTracksUpdate& update
) {
    _webRTC->updatePeerConnectionWithLocalStream(
        streamRoomId, update.audioTracksToRemove,
        joinVideoTracks(update.videoTracksToRemove, update.desktopTracksToRemove), update.audioTracksToAdd,
        joinVideoTracks(update.videoTracksToAdd, update.desktopTracksToAdd), update.dataChannelBeforeUpdate
    );
}

void StreamApiImpl::applyTracksUpdate(const std::shared_ptr<StreamData>& streamData, const StreamTracksUpdate& update) {
    for (const auto& audio : update.audioTracksToAdd) {
        auto trackInfo = streamData->audioTracks.get(audio.first);
        if (trackInfo.has_value()) {
            trackInfo.value()->status = TrackStatus::Published;
        }
    }
    for (const auto& audio : update.audioTracksToRemove) {
        streamData->audioTracks.erase(audio.first);
    }
    for (const auto& video : update.videoTracksToAdd) {
        auto trackInfo = streamData->videoTracks.get(video.first);
        if (!trackInfo.has_value()) {
            continue;
        }
        if (trackInfo.value()->capturer.get() != NULL && !trackInfo.value()->capturer->CaptureStarted()) {
            trackInfo.value()->capturer->StartCapture();
        }
        trackInfo.value()->status = TrackStatus::Published;
    }
    for (const auto& video : update.videoTracksToRemove) {
        auto trackInfo = streamData->videoTracks.get(video.first);
        if (trackInfo.has_value() &&
            trackInfo.value()->capturer.get() != NULL &&
            trackInfo.value()->capturer->CaptureStarted()) {
            trackInfo.value()->capturer->StopCapture();
        }
        streamData->videoTracks.erase(video.first);
    }
    for (const auto& desktop : update.desktopTracksToAdd) {
        auto trackInfo = streamData->desktopTracks.get(desktop.first);
        if (!trackInfo.has_value()) {
            continue;
        }
        if (!trackInfo.value()->capturer->IsRunning()) {
            trackInfo.value()->capturer->Start(trackInfo.value()->fps);
        }
        trackInfo.value()->status = TrackStatus::Published;
    }
    for (const auto& desktop : update.desktopTracksToRemove) {
        auto trackInfo = streamData->desktopTracks.get(desktop.first);
        if (trackInfo.has_value() && trackInfo.value()->capturer->IsRunning()) {
            trackInfo.value()->capturer->Stop();
        }
        streamData->desktopTracks.erase(desktop.first);
    }
    if (streamData->dataTrack) {
        if (streamData->dataTrack->status == TrackStatus::ToAdd) {
            streamData->dataTrack->status = TrackStatus::Published;
        } else if (streamData->dataTrack->status == TrackStatus::ToRemove) {
            streamData->dataTrack = nullptr;
        }
    }
}

StreamApiImpl::VideoTrackList StreamApiImpl::joinVideoTracks(
    const VideoTrackList& videoTracks,
    const VideoTrackList& desktopTracks
) {
    VideoTrackList result{videoTracks};
    result.insert(result.end(), desktopTracks.begin(), desktopTracks.end());
    return result;
}

void StreamApiImpl::removeStream(const StreamHandle& streamHandle) {
    auto streamDataOpt = _streamDataMap.get(streamHandle);
    if (!streamDataOpt.has_value()) {
        throw IncorrectStreamHandleException();
    }
    _streamDataMap.erase(streamHandle);
    _api->removeStream(streamHandle);
}

void StreamApiImpl::expectStreamRemovals(
    const std::string& streamRoomId,
    const std::vector<StreamSubscription>& subscriptionsToRemove
) {
    std::lock_guard<std::mutex> lock(_staleStreamsMutex);
    auto expected = _expectedRemovals.get(streamRoomId).value_or(std::multiset<int64_t>());
    for (const auto& removed : subscriptionsToRemove) {
        expected.insert(removed.streamId);
    }
    _expectedRemovals.set(streamRoomId, expected);
}

void StreamApiImpl::markStreamsAsStale(const std::string& streamRoomId, const std::vector<std::string>& streamIds) {
    std::lock_guard<std::mutex> lock(_staleStreamsMutex);
    auto expected = _expectedRemovals.get(streamRoomId).value_or(std::multiset<int64_t>());
    auto stale = _staleStreams.get(streamRoomId).value_or(std::set<int64_t>());
    for (const auto& streamId : streamIds) {
        int64_t id;
        try {
            id = std::stoll(streamId);
        } catch (...) {
            LOG_ERROR("StreamApiImpl::markStreamsAsStale", "unexpected Stream id '", streamId, "'")
            continue;
        }
        auto awaited = expected.find(id);
        if (awaited != expected.end()) {
            // the track went away because the application unsubscribed, not because the Stream was republished
            expected.erase(awaited);
            continue;
        }
        stale.insert(id);
    }
    _expectedRemovals.set(streamRoomId, expected);
    _staleStreams.set(streamRoomId, stale);
}

void StreamApiImpl::assertStaleStreamsAreRedone(
    const std::string& streamRoomId,
    const std::vector<StreamSubscription>& subscriptionsToAdd,
    const std::vector<StreamSubscription>& subscriptionsToRemove
) {
    auto staleOpt = _staleStreams.get(streamRoomId);
    if (!staleOpt.has_value()) {
        return;
    }
    const auto& stale = staleOpt.value();
    for (const auto& added : subscriptionsToAdd) {
        if (stale.find(added.streamId) == stale.end()) {
            continue;
        }
        bool isRedone = std::any_of(
            subscriptionsToRemove.begin(), subscriptionsToRemove.end(),
            [&](const StreamSubscription& removed) { return removed.streamId == added.streamId; }
        );
        if (!isRedone) {
            throw StreamRequiresResubscriptionException();
        }
    }
}

SubscriberStreamHandle StreamApiImpl::createSubscriberStream(
    const std::string& streamRoomId,
    const std::vector<StreamSubscription>& subscriptions
) {
    auto handle = _api->createSubscriberStream(streamRoomId, subscriptions);
    {
        std::lock_guard<std::mutex> lock(_staleStreamsMutex);
        _staleStreams.erase(streamRoomId);
        _expectedRemovals.erase(streamRoomId);
    }
    _subscriberHandleToRoomId.set(handle, streamRoomId);
    return handle;
}

void StreamApiImpl::updateSubscriberStream(
    const SubscriberStreamHandle& subscriptionHandle,
    const std::vector<StreamSubscription>& subscriptionsToAdd,
    const std::vector<StreamSubscription>& subscriptionsToRemove
) {
    auto streamRoomId = _subscriberHandleToRoomId.get(subscriptionHandle);
    if (streamRoomId.has_value()) {
        assertStaleStreamsAreRedone(streamRoomId.value(), subscriptionsToAdd, subscriptionsToRemove);
        // announced before the call below, because the renegotiation can land before it returns
        expectStreamRemovals(streamRoomId.value(), subscriptionsToRemove);
    }
    _api->updateSubscriberStream(subscriptionHandle, subscriptionsToAdd, subscriptionsToRemove);
    if (!streamRoomId.has_value()) {
        return;
    }
    // a Stream which was subscribed anew or dropped is no longer one the application has to be warned about
    std::lock_guard<std::mutex> lock(_staleStreamsMutex);
    auto staleOpt = _staleStreams.get(streamRoomId.value());
    if (!staleOpt.has_value()) {
        return;
    }
    auto stale = staleOpt.value();
    for (const auto& removed : subscriptionsToRemove) {
        stale.erase(removed.streamId);
    }
    _staleStreams.set(streamRoomId.value(), stale);
}

void StreamApiImpl::removeSubscriberStream(const SubscriberStreamHandle& subscriptionHandle) {
    _api->removeSubscriberStream(subscriptionHandle);
    auto streamRoomId = _subscriberHandleToRoomId.get(subscriptionHandle);
    if (streamRoomId.has_value()) {
        _staleStreams.erase(streamRoomId.value());
    }
    _subscriberHandleToRoomId.erase(subscriptionHandle);
}

std::string StreamApiImpl::createStreamRoom(
    const std::string& contextId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const std::optional<core::ContainerPolicyWithoutItem>& policies,
    const std::optional<int64_t>& emptyRoomTtl
) {
    return _api->createStreamRoom(contextId, users, managers, publicMeta, privateMeta, policies, emptyRoomTtl);
}

void StreamApiImpl::updateStreamRoom(
    const std::string& streamRoomId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const int64_t version,
    const bool force,
    const bool forceGenerateNewKey,
    const std::optional<core::ContainerPolicyWithoutItem>& policies
) {
    _api->updateStreamRoom(
        streamRoomId, users, managers, publicMeta, privateMeta, version, force, forceGenerateNewKey, policies
    );
}

core::PagingList<StreamRoom> StreamApiImpl::listStreamRooms(
    const std::string& contextId,
    const core::PagingQuery& query
) {
    return _api->listStreamRooms(contextId, query);
}

StreamRoom StreamApiImpl::getStreamRoom(const std::string& streamRoomId) {
    return _api->getStreamRoom(streamRoomId);
}

void StreamApiImpl::deleteStreamRoom(const std::string& streamRoomId) {
    _api->deleteStreamRoom(streamRoomId);
}

std::string StreamApiImpl::buildConnectionStateSubscriptionQuery(const std::string& streamRoomId) {
    return std::string(CONNECTION_STATE_CHANNEL) + "|containerId=" + streamRoomId;
}

bool StreamApiImpl::isConnectionStateSubscriptionQuery(const std::string& subscriptionQuery) {
    const std::string channel{CONNECTION_STATE_CHANNEL};
    return subscriptionQuery.rfind(channel, 0) == 0 &&
        (subscriptionQuery.size() == channel.size() || subscriptionQuery[channel.size()] == '|');
}

std::vector<std::string> StreamApiImpl::subscribeFor(const std::vector<std::string>& subscriptionQueries) {
    // the state of the media connections never reaches the Bridge, so its subscriptions are kept here
    // instead of being registered on a channel the server would never publish on
    std::vector<std::string> remoteQueries;
    for (const auto& subscriptionQuery : subscriptionQueries) {
        if (!isConnectionStateSubscriptionQuery(subscriptionQuery)) {
            remoteQueries.push_back(subscriptionQuery);
        }
    }
    std::vector<std::string> remoteIds = remoteQueries.empty() ? std::vector<std::string>() :
                                                                 _api->subscribeFor(remoteQueries);
    std::vector<std::string> result;
    size_t nextRemoteId = 0;
    for (const auto& subscriptionQuery : subscriptionQueries) {
        if (isConnectionStateSubscriptionQuery(subscriptionQuery)) {
            std::string subscriptionId = "local-" + std::to_string(_nextLocalSubscriptionId++);
            _localSubscriptions.set(subscriptionId, subscriptionQuery);
            result.push_back(subscriptionId);
        } else {
            result.push_back(nextRemoteId < remoteIds.size() ? remoteIds[nextRemoteId] : std::string());
            nextRemoteId++;
        }
    }
    return result;
}

void StreamApiImpl::unsubscribeFrom(const std::vector<std::string>& subscriptionIds) {
    std::vector<std::string> remoteIds;
    for (const auto& subscriptionId : subscriptionIds) {
        if (_localSubscriptions.has(subscriptionId)) {
            _localSubscriptions.erase(subscriptionId);
            continue;
        }
        remoteIds.push_back(subscriptionId);
    }
    if (remoteIds.empty()) {
        return;
    }
    return _api->unsubscribeFrom(remoteIds);
}

void StreamApiImpl::setConnectionState(
    const std::string& streamRoomId,
    const std::string& connectionType,
    PeerConnectionState state
) {
    _connectionStateTracker->setConnectionState(streamRoomId, connectionType, state);
}

void StreamApiImpl::emitConnectionStateChangedEvent(const std::string& streamRoomId, StreamConnectionState state) {
    const auto query = buildConnectionStateSubscriptionQuery(streamRoomId);
    std::vector<std::string> subscriptionIds;
    _localSubscriptions.forAll([&](const std::string& subscriptionId, const std::string& subscriptionQuery) {
        if (subscriptionQuery == query) {
            subscriptionIds.push_back(subscriptionId);
        }
    });
    if (subscriptionIds.empty()) {
        return;
    }
    auto event = core::EventBuilder::buildLibEvent<StreamConnectionStateChangedEvent>();
    event->channel = "stream";
    event->data = StreamConnectionStateChangedEventData{.streamRoomId = streamRoomId, .state = state};
    event->subscriptions = subscriptionIds;
    _eventMiddleware->emitApiEvent(event);
}

bool StreamApiImpl::recoverConnection(const std::string& streamRoomId, const std::string& connectionType) {
    if (!_webRTC->getSessionId(streamRoomId, connectionType).has_value()) {
        return false;
    }
    try {
        if (connectionType == "publisher") {
            recoverPublisherConnection(streamRoomId);
        } else {
            // the media server owns the subscriber's offer, so the restart is asked for rather than
            // offered, and the answer to that offer carries new ICE credentials on its own
            _api->restartSubscriberIce(streamRoomId);
        }
    } catch (...) {
        // one failed attempt does not mean the connection cannot be recovered, so it is left to be retried
        LOG_ERROR("StreamApiImpl::recoverConnection", "ICE restart of the ", connectionType, " connection failed")
    }
    return true;
}

void StreamApiImpl::recoverPublisherConnection(const std::string& streamRoomId) {
    auto sessionId = _webRTC->getSessionId(streamRoomId, "publisher");
    _webRTC->restartIce(streamRoomId, "publisher");
    std::string sdp = _webRTC->createOfferAndSetLocalDescription(streamRoomId, "publisher");
    _api->setNewOfferOnReconfigure(sessionId.value(), SdpWithTypeModel{.sdp = sdp, .type = "offer"});
}

std::string StreamApiImpl::buildSubscriptionQuery(
    EventType eventType,
    EventSelectorType selectorType,
    const std::string& selectorId
) {
    return _api->buildSubscriptionQuery(eventType, selectorType, selectorId);
}

void StreamApiImpl::dropBrokenFrames(const std::string& streamRoomId, bool enable) {
    _frameCryptorOptions = privmx::webrtc::FrameCryptorOptions{.dropFrameIfCryptionFailed = enable};
    _webRTC->setFrameCryptorOptions(streamRoomId, _frameCryptorOptions);
}

void StreamApiImpl::addRemoteStreamListener(
    const std::string& streamRoomId,
    std::optional<int64_t> streamId,
    std::shared_ptr<OnTrackInterface> onTrack
) {
    std::optional<std::string> stringStreamId = std::nullopt;
    if (streamId) {
        stringStreamId = std::to_string(streamId.value());
    }
    _webRTC->setOnTrackInterface(streamRoomId, stringStreamId, onTrack);
}

void StreamApiImpl::sendData(const StreamHandle& streamHandle, core::Buffer data) {
    auto streamDataOpt = _streamDataMap.get(streamHandle);
    if (!streamDataOpt.has_value()) {
        throw IncorrectStreamHandleException();
    }
    auto streamData = streamDataOpt.value();
    if (!streamData->dataTrack || streamData->dataTrack->status == TrackStatus::ToAdd) {
        throw DataTrackNotInitializedException();
    }
    streamData->dataTrack->sendData(
        _api->encryptDataChannelMessage(streamData->streamRoomId, {data, streamData->dataTrack->seq.fetch_add(1)})
            .stdString()
    );
}

void StreamApiImpl::processDisconnectedEvent() {
    LOG_TRACE("StreamApiImpl recived DisconnectedEvent");
    // Closure of all remaining capturers
    _streamDataMap.forAllLockSave([]([[maybe_unused]] const StreamHandle& streamHandle,
                                     const std::shared_ptr<StreamData>& streamData) {
        std::lock_guard<std::mutex> lock(streamData->streamMutex);
        streamData->videoTracks.forAll([]([[maybe_unused]] const std::string& id,
                                          const std::shared_ptr<StreamVideoTrackInfo>& video) {
            if (video->capturer.get() != NULL && video->capturer->CaptureStarted()) {
                video->capturer->StopCapture();
            }
        });
        streamData->desktopTracks.forAll([]([[maybe_unused]] const std::string& id,
                                            const std::shared_ptr<StreamDesktopTrackInfo>& desktop) {
            if (desktop->capturer->IsRunning()) {
                desktop->capturer->Stop();
            }
        });
        streamData->status = StreamStatus::Offline;
    });
}

void StreamApiImpl::simulateConnectionLossForTest(const std::string& streamRoomId, const std::string& connectionType) {
    _webRTC->close(streamRoomId, connectionType);
    setConnectionState(streamRoomId, connectionType, PeerConnectionState::PeerConnectionFailed);
}

void StreamApiImpl::reportConnectionFailedForTest(const std::string& streamRoomId, const std::string& connectionType) {
    setConnectionState(streamRoomId, connectionType, PeerConnectionState::PeerConnectionFailed);
}