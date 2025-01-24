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
#include <privmx/endpoint/core/Factory.hpp>
#include <privmx/endpoint/core/ListQueryMapper.hpp>
#include <privmx/crypto/EciesEncryptor.hpp>

#include "privmx/endpoint/stream/StreamApiImpl.hpp"
#include "privmx/endpoint/stream/StreamTypes.hpp"
#include "privmx/endpoint/stream/StreamException.hpp"
#include "privmx/endpoint/stream/DynamicTypes.hpp"


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
    const std::shared_ptr<core::SubscriptionHelper>& contextSubscriptionHelper
) : _gateway(gateway),
    _userPrivKey(userPrivKey),
    _keyProvider(keyProvider),
    _host(host),
    _eventMiddleware(eventMiddleware),
    _contextSubscriptionHelper(contextSubscriptionHelper),
    _serverApi(std::make_shared<ServerApi>(gateway)),
    _streamSubscriptionHelper(core::SubscriptionHelper(eventChannelManager, "stream", "streams")) {
        // streamGetTurnCredentials
        auto model = utils::TypedObjectFactory::createNewObject<server::StreamGetTurnCredentialsModel>();
        model.clientId("user1");
        auto result = _serverApi->streamGetTurnCredentials(model);

        libwebrtc::LibWebRTC::Initialize();
        _peerConnectionFactory = libwebrtc::LibWebRTC::CreateRTCPeerConnectionFactory();
        _configuration = libwebrtc::RTCConfiguration();
        libwebrtc::IceServer iceServer = {
            .uri="turn:webrtc2.s24.simplito:3478", 
            .username=portable::string(result.username()), 
            .password=portable::string(result.password())
        };
        _configuration.ice_servers[0] = iceServer;
        _constraints = libwebrtc::RTCMediaConstraints::Create();
        _notificationListenerId = _eventMiddleware->addNotificationEventListener(std::bind(&StreamApiImpl::processNotificationEvent, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
        _connectedListenerId = _eventMiddleware->addConnectedEventListener(std::bind(&StreamApiImpl::processConnectedEvent, this));
        _disconnectedListenerId = _eventMiddleware->addDisconnectedEventListener(std::bind(&StreamApiImpl::processDisconnectedEvent, this));
    }

StreamApiImpl::~StreamApiImpl() {
    _streamRoomMap.forAll([&](std::string key, std::shared_ptr<privmx::endpoint::stream::StreamApiImpl::StreamRoomData> value) {
        for(auto stream: value->streamMap) {
            stream.second->peerConnection->Close();
        }
        value->streamMap.clear();
    });
    _streamRoomMap.clear();
    _eventMiddleware->removeNotificationEventListener(_notificationListenerId);
    _eventMiddleware->removeConnectedEventListener(_connectedListenerId);
    _eventMiddleware->removeDisconnectedEventListener(_disconnectedListenerId);
}


void StreamApiImpl::processNotificationEvent(const std::string& type, const std::string& channel, const Poco::JSON::Object::Ptr& data) {
    // if(type == "custom" && channel.length() >= 8+9 && channel.substr(0, 8) == "context/" && channel.substr(channel.length()-9, 9) == "/internal") {
    //     auto raw = utils::TypedObjectFactory::createObjectFromVar<core::server::ContextCustomEventData>(data);
    //     if(_contextSubscriptionHelper->hasSubscriptionForElementCustom(raw.id(), "internal")) { // needs proper class to handle
    //         auto rawEventData = utils::TypedObjectFactory::createObjectFromVar<core::server::CustomEventData>(privmx::utils::Utils::parseJson(raw.eventData()));
    //         if(!rawEventData.typeEmpty() && rawEventData.type() == "StreamKeyManagementEvent") {
    //             auto encKey = privmx::crypto::EciesEncryptor::decryptFromBase64(_userPrivKey, raw.key());
    //             auto decrypted = _dataEncryptor.decodeAndDecryptAndVerify(rawEventData.encryptedData().convert<std::string>(), _userPrivKey.getPublicKey(), encKey);
    //             std::cout << decrypted.stdString() << std::endl;
    //             auto streamKeyManagementEvent = utils::TypedObjectFactory::createObjectFromVar<server::StreamKeyManagementEvent>(privmx::utils::Utils::parseJson(decrypted.stdString()));
    //             auto roomOpt = _streamRoomMap.get(streamKeyManagementEvent.streamRoomId());
    //             if(roomOpt.has_value()) {
    //                 roomOpt.value()->streamKeyManager->respondToEvent(streamKeyManagementEvent, raw.author().id(), raw.author().pub());
    //             }
    //         }
    //     }
    // }
}

void StreamApiImpl::processConnectedEvent() {

}

void StreamApiImpl::processDisconnectedEvent() {

}
// V3 code 

int64_t StreamApiImpl::createStream(const std::string& streamRoomId) {
    auto roomOpt = _streamRoomMap.get(streamRoomId);
    if(!roomOpt.has_value()) {
        auto model = privmx::utils::TypedObjectFactory::createNewObject<server::StreamRoomGetModel>();
        model.id(streamRoomId);
        auto streamRoom = _serverApi->streamRoomGet(model).streamRoom();
        _streamRoomMap.set(
            streamRoomId,
            std::make_shared<StreamRoomData>(
                StreamRoomData{
                    .streamMap=std::map<uint64_t, std::shared_ptr<Stream>>(), 
                    .streamKeyManager=std::make_shared<StreamKeyManager>(_keyProvider, _serverApi, _userPrivKey, streamRoomId, streamRoom.contextId(), _contextSubscriptionHelper),
                }
            )
        );
        roomOpt = _streamRoomMap.get(streamRoomId);
    }
    auto room = roomOpt.value();
    int64_t streamId = generateNumericId();
    PRIVMX_DEBUG("STREAMS", "API", std::to_string(streamId) + ": STREAM Sender")
    _streamIdToRoomId.set(streamId, streamRoomId);
    room->streamMap.emplace(
        std::make_pair(
            streamId, 
            std::make_shared<Stream>(
                Stream{
                    .peerConnection=_peerConnectionFactory->Create(
                        _configuration, 
                        _constraints
                    ),
                    .peerConnectionObserver=std::make_shared<PmxPeerConnectionObserver>(
                        streamId,
                        room->streamKeyManager,
                        []([[maybe_unused]] int64_t w, [[maybe_unused]] int64_t h, [[maybe_unused]] std::shared_ptr<Frame> frame, [[maybe_unused]] const std::string& id) {}
                    )
                }
            )
        )
    );
    auto stream = room->streamMap.at(streamId);
    stream->peerConnection->RegisterRTCPeerConnectionObserver(stream->peerConnectionObserver.get());
    return streamId;
}

// Adding track
std::vector<std::pair<int64_t, std::string>> StreamApiImpl::listAudioRecordingDevices() {  
    std::string name, deviceId;
    name.resize(255);
    deviceId.resize(255);
    _audioDevice = _peerConnectionFactory->GetAudioDevice();
    uint32_t num = _audioDevice->RecordingDevices();
    std::vector<std::pair<int64_t, std::string>> result;
    for (uint32_t i = 0; i < num; ++i) {
        _audioDevice->RecordingDeviceName(i, (char*)name.data(), (char*)deviceId.data());
        result.push_back(std::make_pair((int64_t)i, name));
    }
    return result;
}

std::vector<std::pair<int64_t, std::string>> StreamApiImpl::listVideoRecordingDevices() {
    std::string name, deviceId;
    name.resize(255);
    deviceId.resize(255);
    _videoDevice = _peerConnectionFactory->GetVideoDevice();
    uint32_t num = _videoDevice->NumberOfDevices();
    std::vector<std::pair<int64_t, std::string>> result;
    for (uint32_t i = 0; i < num; ++i) {
        _videoDevice->GetDeviceName(i, (char*)name.data(), name.size(), (char*)deviceId.data(), deviceId.size());
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
    if(_audioDevice == nullptr) _audioDevice = _peerConnectionFactory->GetAudioDevice();
    _audioDevice->SetRecordingDevice(id);
    auto audioSource = _peerConnectionFactory->CreateAudioSource("audio_source");
    auto audioTrack = _peerConnectionFactory->CreateAudioTrack(audioSource, "audio_track");
    audioTrack->SetVolume(10);
    // Add tracks to the peer connection
    auto streamRoomId = _streamIdToRoomId.get(streamId);
    if(!streamRoomId.has_value()) {
        throw IncorrectStreamIdException();
    }
    auto room = _streamRoomMap.get(streamRoomId.value()).value();
    auto sender = room->streamMap.at(streamId)->peerConnection->AddTrack(audioTrack, libwebrtc::vector<libwebrtc::string>{std::vector<libwebrtc::string>{std::to_string(streamId)}});
    std::shared_ptr<privmx::webrtc::FrameCryptor> frameCryptor = privmx::webrtc::FrameCryptorFactory::frameCryptorFromRtpSender(sender, room->streamKeyManager->getCurrentWebRtcKeyStore());
    room->streamKeyManager->addFrameCryptor(frameCryptor);
}

void StreamApiImpl::trackAddVideo(int64_t streamId, int64_t id, const std::string& params_JSON) {
    if(_videoDevice == nullptr) _videoDevice = _peerConnectionFactory->GetVideoDevice();
    libwebrtc::scoped_refptr<libwebrtc::RTCVideoDevice> videoDevice = _peerConnectionFactory->GetVideoDevice();
    // params_JSON
    libwebrtc::scoped_refptr<libwebrtc::RTCVideoCapturer> videoCapturer = videoDevice->Create("video_capturer", id, 1280, 720, 30);
    libwebrtc::scoped_refptr<libwebrtc::RTCVideoSource> videoSource = _peerConnectionFactory->CreateVideoSource(videoCapturer, "video_source", _constraints);
    libwebrtc::scoped_refptr<libwebrtc::RTCVideoTrack> videoTrack = _peerConnectionFactory->CreateVideoTrack(videoSource, "video_track");

    // Add tracks to the peer connection
    auto streamRoomId = _streamIdToRoomId.get(streamId);
    if(!streamRoomId.has_value()) {
        throw IncorrectStreamIdException();
    }
    auto room = _streamRoomMap.get(streamRoomId.value()).value();
    auto sender = room->streamMap.at(streamId)->peerConnection->AddTrack(videoTrack, libwebrtc::vector<libwebrtc::string>{std::vector<libwebrtc::string>{std::to_string(streamId)}});
    std::shared_ptr<privmx::webrtc::FrameCryptor> frameCryptor = privmx::webrtc::FrameCryptorFactory::frameCryptorFromRtpSender(sender, room->streamKeyManager->getCurrentWebRtcKeyStore());
    room->streamKeyManager->addFrameCryptor(frameCryptor);
    // Start capture video
    videoCapturer->StartCapture();
}

void StreamApiImpl::trackAddDesktop(int64_t streamId, int64_t id, const std::string& params_JSON) {
    throw stream::NotImplementedException();
}

// Publishing stream
void StreamApiImpl::publishStream(int64_t streamId) {
    auto streamRoomId = _streamIdToRoomId.get(streamId);
    if(!streamRoomId.has_value()) {
        throw IncorrectStreamIdException();
    }
    auto room = _streamRoomMap.get(streamRoomId.value()).value();
    libwebrtc::scoped_refptr<libwebrtc::RTCPeerConnection> peerConnection = room->streamMap.at(streamId)->peerConnection;
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
    // Publish data on bridge
    auto sessionDescription = utils::TypedObjectFactory::createNewObject<server::SessionDescription>();
    sessionDescription.sdp(sdp);
    sessionDescription.type("offer");
    auto model = utils::TypedObjectFactory::createNewObject<server::StreamPublishModel>();
    model.streamRoomId(1234); //TODO
    model.offer(sessionDescription);
    auto result = _serverApi->streamPublish(model);
    // Set remote description
    peerConnection->SetRemoteDescription(
        result.answer().sdp(), 
        result.answer().type(),
        [&]() {}, 
        [&](const char* error) {
            throw stream::WebRTCException("OnSetSdpFailure" + std::string(error));
        }
    );
}

// // Joining to Stream
void StreamApiImpl::joinStream(const std::string& streamRoomId, const std::vector<int64_t>& streamsId, const streamJoinSettings& settings) {
    auto roomOpt = _streamRoomMap.get(streamRoomId);
    if(!roomOpt.has_value()) {
        auto model = privmx::utils::TypedObjectFactory::createNewObject<server::StreamRoomGetModel>();
        model.id(streamRoomId);
        auto streamRoom = _serverApi->streamRoomGet(model).streamRoom(); 
        _streamRoomMap.set(
            streamRoomId,
            std::make_shared<StreamRoomData>(
                StreamRoomData{
                    .streamMap=std::map<uint64_t, std::shared_ptr<Stream>>(), 
                    .streamKeyManager=std::make_shared<StreamKeyManager>(_keyProvider, _serverApi, _userPrivKey, streamRoomId, streamRoom.contextId(), _contextSubscriptionHelper),
                }
            )
        );
        roomOpt = _streamRoomMap.get(streamRoomId);
    }
    auto room = roomOpt.value();
    int64_t streamId = generateNumericId();
    PRIVMX_DEBUG("STREAMS", "API", std::to_string(streamId) + ": STREAM Receiver")
    _streamIdToRoomId.set(streamId, streamRoomId);
    // Get data from bridge
    auto streamJoinModel = utils::TypedObjectFactory::createNewObject<server::StreamJoinModel>();
    streamJoinModel.streamIds(utils::TypedObjectFactory::createNewList<int64_t>());
    for(size_t i = 0; i < streamsId.size(); i++) {
        streamJoinModel.streamIds().add(streamsId[i]);
    }
    streamJoinModel.streamRoomId(1234); //TODO
    auto streamJoinResult = _serverApi->streamJoin(streamJoinModel);
    // creating peerConnectio
    room->streamMap.emplace(
        std::make_pair(
            streamId, 
            std::make_shared<Stream>(
                Stream{
                    .peerConnection=_peerConnectionFactory->Create(
                        _configuration,
                        _constraints
                    ),
                    .peerConnectionObserver=std::make_shared<PmxPeerConnectionObserver>(
                        streamId,
                        room->streamKeyManager,
                        settings.OnFrame.has_value() ? 
                            settings.OnFrame.value() : 
                            []([[maybe_unused]] int64_t w, [[maybe_unused]] int64_t h, [[maybe_unused]] std::shared_ptr<Frame> frame, [[maybe_unused]] const std::string& id) {}
                    )
                }
            )
        )
    );
    auto stream = room->streamMap.at(streamId);
    auto peerConnection = stream->peerConnection;
    peerConnection->RegisterRTCPeerConnectionObserver(stream->peerConnectionObserver.get());
    // Set remote description
    peerConnection->SetRemoteDescription(
        streamJoinResult.offer().sdp(), 
        streamJoinResult.offer().type(),
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
    std::string sdp = t_spd.get_future().get();
    peerConnection->SetLocalDescription(
        sdp, 
        "answer",
        [&]() {}, 
        [&](const char* error) {
            throw stream::WebRTCException("OnSetSdpFailure" + std::string(error));
        }
    );
    auto sessionDescription = utils::TypedObjectFactory::createNewObject<server::SessionDescription>();
    sessionDescription.sdp(sdp);
    sessionDescription.type("answer");
    auto model = utils::TypedObjectFactory::createNewObject<server::StreamAcceptOfferModel>();
    model.sessionId(streamJoinResult.sessionId());
    model.answer(sessionDescription);
    _serverApi->streamAcceptOffer(model);
    // get userId
    room->streamKeyManager->requestKey({core::UserWithPubKey{.userId="user1", .pubKey="8RUGiizsLszXAfWXEaPxjrcnXCsgd48zCHmmK6ng2cZCquMoeZ"}});
}

std::string StreamApiImpl::createStreamRoom(
    const std::string& contextId, 
    const std::vector<core::UserWithPubKey>& users, 
    const std::vector<core::UserWithPubKey>&managers,
    const core::Buffer& publicMeta, 
    const core::Buffer& privateMeta,
    const std::optional<core::ContainerPolicy>& policies
) {
    PRIVMX_DEBUG_TIME_START(PlatformStream, createStreamRoom)
    auto streamRoomKey = _keyProvider->generateKey();
    StreamRoomDataToEncrypt streamRoomDataToEncrypt {
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .internalMeta = std::nullopt
    };
    auto create_stream_room_model = utils::TypedObjectFactory::createNewObject<server::StreamRoomCreateModel>();
    create_stream_room_model.contextId(contextId);
    create_stream_room_model.keyId(streamRoomKey.id);
    create_stream_room_model.data(_streamRoomDataEncryptorV4.encrypt(streamRoomDataToEncrypt, _userPrivKey, streamRoomKey.key).asVar());
    auto allUsers = core::EndpointUtils::uniqueListUserWithPubKey(users, managers);
    privmx::utils::List<core::server::KeyEntrySet> keys = _keyProvider->prepareKeysList(allUsers, streamRoomKey);
    create_stream_room_model.keys(keys);
    create_stream_room_model.users(mapUsers(users));
    create_stream_room_model.managers(mapUsers(managers));
    if (policies.has_value()) {
        create_stream_room_model.policy(core::Factory::createPolicyServerObject(policies.value()));
    }

    auto result = _serverApi->streamRoomCreate(create_stream_room_model);
    PRIVMX_DEBUG_TIME_STOP(PlatformStream, createStreamRoom, data send)
    return result.streamRoomId();
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
    PRIVMX_DEBUG_TIME_START(PlatformStream, updateStreamRoom)
    // get current streamRoom
    auto getModel = utils::TypedObjectFactory::createNewObject<server::StreamRoomGetModel>();
    getModel.id(streamRoomId);
    auto currentStreamRoom = _serverApi->streamRoomGet(getModel).streamRoom();
    // extract current users info
    auto usersVec {core::EndpointUtils::listToVector<std::string>(currentStreamRoom.users())};
    auto managersVec {core::EndpointUtils::listToVector<std::string>(currentStreamRoom.managers())};
    auto oldUsersAll {core::EndpointUtils::uniqueList(usersVec, managersVec)};
    auto new_users = core::EndpointUtils::uniqueListUserWithPubKey(users, managers);
    // adjust key
    std::vector<std::string> usersDiff {core::EndpointUtils::getDifference(oldUsersAll, core::EndpointUtils::usersWithPubKeyToIds(new_users))};
    bool needNewKey = usersDiff.size() > 0;

    auto currentKey {_keyProvider->getKey(currentStreamRoom.keys(), currentStreamRoom.keyId())};
    auto streamRoomKey = forceGenerateNewKey || needNewKey ? _keyProvider->generateKey() : currentKey; 

    auto model = utils::TypedObjectFactory::createNewObject<server::StreamRoomUpdateModel>();
    model.id(streamRoomId);
    model.keyId(streamRoomKey.id);
    model.keys(_keyProvider->prepareKeysList(new_users, streamRoomKey));
    auto usersList = utils::TypedObjectFactory::createNewList<std::string>();
    for (auto user: users) {
        usersList.add(user.userId);
    }
    auto managersList = utils::TypedObjectFactory::createNewList<std::string>();
    for (auto x: managers) {
        managersList.add(x.userId);
    }
    model.users(usersList);
    model.managers(managersList);
    model.version(version);
    model.force(force);
    if (policies.has_value()) {
        model.policy(privmx::endpoint::core::Factory::createPolicyServerObject(policies.value()));
    }
    StreamRoomDataToEncrypt streamRoomDataToEncrypt {
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .internalMeta = std::nullopt
    };
    model.data(_streamRoomDataEncryptorV4.encrypt(streamRoomDataToEncrypt, _userPrivKey, streamRoomKey.key).asVar());

    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStream, updateStreamRoom, data encrypted)
    _serverApi->streamRoomUpdate(model);
    PRIVMX_DEBUG_TIME_STOP(PlatformStream, updateStreamRoom, data send)
}

core::PagingList<StreamRoom> StreamApiImpl::listStreamRooms(const std::string& contextId, const core::PagingQuery& query) {
    PRIVMX_DEBUG_TIME_START(PlatformStream, listStreamRooms)
    auto model = utils::TypedObjectFactory::createNewObject<server::StreamRoomListModel>();
    model.contextId(contextId);
    core::ListQueryMapper::map(model, query);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStream, listStreamRooms, getting listStreamRooms)
    auto streamRoomsList = _serverApi->streamRoomList(model);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStream, listStreamRooms, data send)
    std::vector<StreamRoom> streamRooms;
    for (auto streamRoom : streamRoomsList.list()) {
        streamRooms.push_back(decryptAndConvertStreamRoomDataToStreamRoom(streamRoom));
    }
    PRIVMX_DEBUG_TIME_STOP(PlatformStream, listStreamRooms, data decrypted)
    return core::PagingList<StreamRoom>({
        .totalAvailable = streamRoomsList.count(),
        .readItems = streamRooms
    });
}

StreamRoom StreamApiImpl::getStreamRoom(const std::string& streamRoomId) {
    PRIVMX_DEBUG_TIME_START(PlatformStream, getStreamRoom)
    auto model = utils::TypedObjectFactory::createNewObject<server::StreamRoomGetModel>();
    model.id(streamRoomId);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStream, getStreamRoom, getting streamRoom)
    auto streamRoom = _serverApi->streamRoomGet(model);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStream, getStreamRoom, data send)
    auto result = decryptAndConvertStreamRoomDataToStreamRoom(streamRoom.streamRoom());
    PRIVMX_DEBUG_TIME_STOP(PlatformStream, getStreamRoom, data decrypted)
    return result;
}

void StreamApiImpl::deleteStreamRoom(const std::string& streamRoomId) {
    PRIVMX_DEBUG_TIME_START(PlatformStream, deleteStreamRoom)
    auto model = utils::TypedObjectFactory::createNewObject<server::StreamRoomDeleteModel>();
    model.streamRoomId(streamRoomId);
    _serverApi->streamRoomDelete(model);
    PRIVMX_DEBUG_TIME_STOP(PlatformStream, deleteStreamRoom)
}

DecryptedStreamRoomData StreamApiImpl::decryptStreamRoomV4(const server::StreamRoomInfo& streamRoom) {
    try {
        auto streamRoomDataEntry = streamRoom.data().get(streamRoom.data().size()-1);
        auto key = _keyProvider->getKey(streamRoom.keys(), streamRoomDataEntry.keyId());
        auto encryptedStreamRoomData = utils::TypedObjectFactory::createObjectFromVar<server::EncryptedStreamRoomDataV4>(streamRoomDataEntry.data());
        return _streamRoomDataEncryptorV4.decrypt(encryptedStreamRoomData, key.key);
    } catch (const core::Exception& e) {
        return DecryptedStreamRoomData({{},{},{},{},.statusCode = e.getCode()});
    } catch (const privmx::utils::PrivmxException& e) {
        return DecryptedStreamRoomData({{},{},{},{},.statusCode = core::ExceptionConverter::convert(e).getCode()});
    } catch (...) {
        return DecryptedStreamRoomData({{},{},{},{},.statusCode = ENDPOINT_CORE_EXCEPTION_CODE});
    }
}

StreamRoom StreamApiImpl::convertDecryptedStreamRoomDataToStreamRoom(const server::StreamRoomInfo& streamRoomInfo, const DecryptedStreamRoomData& streamRoomData) {
    std::vector<std::string> users;
    std::vector<std::string> managers;
    for (auto x : streamRoomInfo.users()) {
        users.push_back(x);
    }
    for (auto x : streamRoomInfo.managers()) {
        managers.push_back(x);
    }

    return {
        .contextId = streamRoomInfo.contextId(),
        .streamRoomId = streamRoomInfo.id(),
        .createDate = streamRoomInfo.createDate(),
        .creator = streamRoomInfo.creator(),
        .lastModificationDate = streamRoomInfo.lastModificationDate(),
        .lastModifier = streamRoomInfo.lastModifier(),
        .users = users,
        .managers = managers,
        .version = streamRoomInfo.version(),
        .publicMeta = streamRoomData.publicMeta,
        .privateMeta = streamRoomData.privateMeta,
        .policy = core::Factory::parsePolicyServerObject(streamRoomInfo.policy()), 
        .statusCode = streamRoomData.statusCode
    };
}

StreamRoom StreamApiImpl::decryptAndConvertStreamRoomDataToStreamRoom(const server::StreamRoomInfo& streamRoom) {
    auto storDdataEntry = streamRoom.data().get(streamRoom.data().size()-1);
    auto versioned = utils::TypedObjectFactory::createObjectFromVar<dynamic::VersionedData>(storDdataEntry.data());
    if (!versioned.versionEmpty() && versioned.version() == 4) {
        return convertDecryptedStreamRoomDataToStreamRoom(streamRoom, decryptStreamRoomV4(streamRoom));
    }
    auto e = UnknowStreamRoomFormatException();
    return StreamRoom{{},{},{},{},{},{},{},{},{},{},{},{}, .statusCode = e.getCode()};
}

int64_t StreamApiImpl::generateNumericId() {
    return std::rand();
}

privmx::utils::List<std::string> StreamApiImpl::mapUsers(const std::vector<core::UserWithPubKey>& users) {
    auto result = privmx::utils::TypedObjectFactory::createNewList<std::string>();
    for (auto user : users) {
        result.add(user.userId);
    }
    return result;
}