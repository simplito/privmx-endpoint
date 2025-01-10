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

using namespace privmx::endpoint;
using namespace privmx::endpoint::stream;

StreamApiImpl::StreamApiImpl(
    const privfs::RpcGateway::Ptr& gateway,
    const privmx::crypto::PrivateKey& userPrivKey,
    const std::shared_ptr<core::KeyProvider>& keyProvider,
    const std::string& host,
    const std::shared_ptr<core::EventMiddleware>& eventMiddleware,
    const std::shared_ptr<core::EventChannelManager>& eventChannelManager,
    const core::Connection& connection
) : _gateway(gateway),
    _userPrivKey(userPrivKey),
    _keyProvider(keyProvider),
    _host(host),
    _eventMiddleware(eventMiddleware),
    _connection(connection),
    _serverApi(ServerApi(gateway)) {
        // streamGetTurnCredentials
        auto model = utils::TypedObjectFactory::createNewObject<server::StreamGetTurnCredentialsModel>();
        model.clientId("user1");
        auto result = _serverApi.streamGetTurnCredentials(model);

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

    }


// V3 code 

int64_t StreamApiImpl::createStream(const std::string& streamRoomId) {
    int64_t streamId = generateNumericId();
    _peerConnectionMap.emplace(
        std::make_pair(
            streamId, 
            _peerConnectionFactory->Create(
                _configuration, 
                _constraints
            )
        )
    );
    _pmxPeerConnectionObserverMap.emplace(
        std::make_pair(
            streamId, 
            PmxPeerConnectionObserver(
                []([[maybe_unused]] int64_t w, [[maybe_unused]] int64_t h, [[maybe_unused]] std::shared_ptr<Frame> frame, [[maybe_unused]] const std::string& id) {},
                streamId
            )
        )
    );
    _peerConnectionMap.at(streamId)->RegisterRTCPeerConnectionObserver(&_pmxPeerConnectionObserverMap.at(streamId));
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
   throw stream::NotImplementedException();
}

std::vector<std::pair<int64_t, std::string>> StreamApiImpl::listDesktopRecordingDevices() {
   throw stream::NotImplementedException();
}
// int64_t id, DeviceType type, const std::string& params_JSON can be merged to one struct [Track info]
void StreamApiImpl::trackAdd(int64_t streamId, int64_t id, DeviceType type, const std::string& params_JSON) {
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
    // _audioDevice->SetRecordingDevice(id);
    auto audioSource = _peerConnectionFactory->CreateAudioSource("audio_source");
    auto audioTrack = _peerConnectionFactory->CreateAudioTrack(audioSource, "audio_track");
    audioTrack->SetVolume(10);
    _peerConnectionMap.at(streamId)->AddTrack(audioTrack, libwebrtc::vector<libwebrtc::string>{std::vector<libwebrtc::string>{std::to_string(streamId)}});
}
void StreamApiImpl::trackAddVideo(int64_t streamId, int64_t id, const std::string& params_JSON) {
    throw stream::NotImplementedException();
}
void StreamApiImpl::trackAddDesktop(int64_t streamId, int64_t id, const std::string& params_JSON) {
    throw stream::NotImplementedException();
}

// Publishing stream
void StreamApiImpl::publishStream(int64_t streamId) {
    libwebrtc::scoped_refptr<libwebrtc::RTCPeerConnection> peerConnection = _peerConnectionMap.at(streamId);
    std::cout << peerConnection->ice_gathering_state() << std::endl;
    std::promise<std::string> t_spd = std::promise<std::string>();
    peerConnection->CreateOffer(
        [&](const libwebrtc::string sdp, const libwebrtc::string type) {
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
            // throw stream::WebRTCException("OnSetSdpFailure" + std::string(error));
        }
    );
    // Publish data on bridge
    auto sessionDescription = utils::TypedObjectFactory::createNewObject<server::SessionDescription>();
    sessionDescription.sdp(sdp);
    sessionDescription.type("offer");
    auto model = utils::TypedObjectFactory::createNewObject<server::StreamPublishModel>();
    model.streamRoomId(1234);
    model.offer(sessionDescription);
    auto result = _serverApi.streamPublish(model);
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
    int64_t streamId = generateNumericId();
    _peerConnectionMap.emplace(
        std::make_pair(
            streamId, 
            _peerConnectionFactory->Create(
                _configuration, 
                _constraints
            )
        )
    );
    _pmxPeerConnectionObserverMap.emplace(
        std::make_pair(
            streamId, 
            PmxPeerConnectionObserver(
                settings.OnFrame.has_value() ? settings.OnFrame.value() : []([[maybe_unused]] int64_t w, [[maybe_unused]] int64_t h, [[maybe_unused]] std::shared_ptr<Frame> frame, [[maybe_unused]] const std::string& id) {},
                streamId
            )
        )
    );
    auto peerConnection = _peerConnectionMap.at(streamId);
    peerConnection->RegisterRTCPeerConnectionObserver(&_pmxPeerConnectionObserverMap.at(streamId));
    // Get data from bridge
    auto streamJoinModel = utils::TypedObjectFactory::createNewObject<server::StreamJoinModel>();
    streamJoinModel.streamIds(utils::TypedObjectFactory::createNewList<int64_t>());
    for(size_t i = 0; i < streamsId.size(); i++) {
        streamJoinModel.streamIds().add(streamsId[i]);
    }
    streamJoinModel.streamRoomId(1234);
    auto streamJoinResult = _serverApi.streamJoin(streamJoinModel);
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
        [&](const libwebrtc::string sdp, const libwebrtc::string type) {
            t_spd.set_value(sdp.std_string());
        },
        [&](const char* error) {
            throw stream::WebRTCException("SdpCreateFailure" + std::string(error));
        }, 
        _constraints
    );
    std::string sdp = t_spd.get_future().get();
    auto sessionDescription = utils::TypedObjectFactory::createNewObject<server::SessionDescription>();
    sessionDescription.sdp(sdp);
    sessionDescription.type("answer");
    auto model = utils::TypedObjectFactory::createNewObject<server::StreamAcceptOfferModel>();
    model.sessionId(streamJoinResult.sessionId());
    model.answer(sessionDescription);
    _serverApi.streamAcceptOffer(model);
}


// // V2 code

// std::string StreamApiImpl::roomCreate(
//     const std::string& contextId, 
//     const std::vector<core::UserWithPubKey>& users, 
//     const std::vector<core::UserWithPubKey>&managers,
//     const core::Buffer& publicMeta, 
//     const core::Buffer& privateMeta,
//     const std::optional<core::ContainerPolicy>& policies
// ) {
//     PRIVMX_DEBUG_TIME_START(PlatformStream, roomCreate)
//     auto streamRoomKey = _keyProvider->generateKey();
//     StreamRoomDataToEncrypt streamRoomDataToEncrypt {
//         .publicMeta = publicMeta,
//         .privateMeta = privateMeta,
//         .internalMeta = std::nullopt
//     };
//     auto create_stream_room_model = utils::TypedObjectFactory::createNewObject<server::StreamRoomCreateModel>();
//     create_stream_room_model.contextId(contextId);
//     create_stream_room_model.keyId(streamRoomKey.id);
//     create_stream_room_model.data(_streamRoomDataEncryptorV4.encrypt(streamRoomDataToEncrypt, _userPrivKey, streamRoomKey.key).asVar());
//     auto allUsers = core::EndpointUtils::uniqueListUserWithPubKey(users, managers);
//     privmx::utils::List<core::server::KeyEntrySet> keys = _keyProvider->prepareKeysList(allUsers, streamRoomKey);
//     create_stream_room_model.keys(keys);
//     create_stream_room_model.users(mapUsers(users));
//     create_stream_room_model.managers(mapUsers(managers));
//     if (policies.has_value()) {
//         create_stream_room_model.policy(core::Factory::createPolicyServerObject(policies.value()));
//     }

//     auto result = _serverApi.streamRoomCreate(create_stream_room_model);
//     PRIVMX_DEBUG_TIME_STOP(PlatformStream, roomCreate, data send)
//     return result.streamRoomId();
// }

// void StreamApiImpl::roomUpdate(
//     const std::string& streamRoomId, 
//     const std::vector<core::UserWithPubKey>& users, 
//     const std::vector<core::UserWithPubKey>&managers,
//     const core::Buffer& publicMeta, 
//     const core::Buffer& privateMeta, 
//     const int64_t version, 
//     const bool force, 
//     const bool forceGenerateNewKey, 
//     const std::optional<core::ContainerPolicy>& policies
// ) {
//     PRIVMX_DEBUG_TIME_START(PlatformStream, roomUpdate)
//     // get current streamRoom
//     auto getModel = utils::TypedObjectFactory::createNewObject<server::StreamRoomGetModel>();
//     getModel.streamRoomId(streamRoomId);
//     auto currentStreamRoom = _serverApi.streamRoomGet(getModel).streamRoom();
//     // extract current users info
//     auto usersVec {core::EndpointUtils::listToVector<std::string>(currentStreamRoom.users())};
//     auto managersVec {core::EndpointUtils::listToVector<std::string>(currentStreamRoom.managers())};
//     auto oldUsersAll {core::EndpointUtils::uniqueList(usersVec, managersVec)};
//     auto new_users = core::EndpointUtils::uniqueListUserWithPubKey(users, managers);
//     // adjust key
//     std::vector<std::string> usersDiff {core::EndpointUtils::getDifference(oldUsersAll, core::EndpointUtils::usersWithPubKeyToIds(new_users))};
//     bool needNewKey = usersDiff.size() > 0;

//     auto currentKey {_keyProvider->getKey(currentStreamRoom.keys(), currentStreamRoom.keyId())};
//     auto streamRoomKey = forceGenerateNewKey || needNewKey ? _keyProvider->generateKey() : currentKey; 

//     auto model = utils::TypedObjectFactory::createNewObject<server::StreamRoomUpdateModel>();
//     model.id(streamRoomId);
//     model.keyId(streamRoomKey.id);
//     model.keys(_keyProvider->prepareKeysList(new_users, streamRoomKey));
//     auto usersList = utils::TypedObjectFactory::createNewList<std::string>();
//     for (auto user: users) {
//         usersList.add(user.userId);
//     }
//     auto managersList = utils::TypedObjectFactory::createNewList<std::string>();
//     for (auto x: managers) {
//         managersList.add(x.userId);
//     }
//     model.users(usersList);
//     model.managers(managersList);
//     model.version(version);
//     model.force(force);
//     if (policies.has_value()) {
//         model.policy(privmx::endpoint::core::Factory::createPolicyServerObject(policies.value()));
//     }
//     StreamRoomDataToEncrypt streamRoomDataToEncrypt {
//         .publicMeta = publicMeta,
//         .privateMeta = privateMeta,
//         .internalMeta = std::nullopt
//     };
//     model.data(_streamRoomDataEncryptorV4.encrypt(streamRoomDataToEncrypt, _userPrivKey, streamRoomKey.key).asVar());

//     PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStream, roomUpdate, data encrypted)
//     _serverApi.streamRoomUpdate(model);
//     PRIVMX_DEBUG_TIME_STOP(PlatformStream, roomUpdate, data send)
// }

// core::PagingList<StreamRoom> StreamApiImpl::streamRoomList(const std::string& contextId, const core::PagingQuery& query) {
//     PRIVMX_DEBUG_TIME_START(PlatformStream, streamRoomList)
//     auto model = utils::TypedObjectFactory::createNewObject<server::StreamRoomListModel>();
//     model.contextId(contextId);
//     core::ListQueryMapper::map(model, query);
//     PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStream, streamRoomList, getting streamRoomList)
//     auto streamRoomsList = _serverApi.streamRoomList(model);
//     PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStream, streamRoomList, data send)
//     std::vector<StreamRoom> streamRooms;
//     for (auto streamRoom : streamRoomsList.streamRooms()) {
//         streamRooms.push_back(decryptAndConvertStreamRoomDataToStreamRoom(streamRoom));
//     }
//     PRIVMX_DEBUG_TIME_STOP(PlatformStream, streamRoomList, data decrypted)
//     return core::PagingList<StreamRoom>({
//         .totalAvailable = streamRoomsList.count(),
//         .readItems = streamRooms
//     });
// }

// StreamRoom StreamApiImpl::streamRoomGet(const std::string& streamRoomId) {
//     PRIVMX_DEBUG_TIME_START(PlatformStream, streamRoomGet)
//     auto model = utils::TypedObjectFactory::createNewObject<server::StreamRoomGetModel>();
//     model.streamRoomId(streamRoomId);
//     PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStream, streamRoomGet, getting streamRoom)
//     auto streamRoom = _serverApi.streamRoomGet(model);
//     PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStream, streamRoomGet, data send)
//     auto result = decryptAndConvertStreamRoomDataToStreamRoom(streamRoom.streamRoom());
//     PRIVMX_DEBUG_TIME_STOP(PlatformStream, streamRoomGet, data decrypted)
//     return result;
// }

// void StreamApiImpl::streamRoomDelete(const std::string& streamRoomId) {
//     auto model = utils::TypedObjectFactory::createNewObject<server::StreamRoomDeleteModel>();
//     model.streamRoomId(streamRoomId);
//     _serverApi.streamRoomDelete(model);
// }

// DecryptedStreamRoomData StreamApiImpl::decryptStreamRoomV4(const server::StreamRoomInfo& streamRoom) {
//     try {
//         auto streamRoomDataEntry = streamRoom.data().get(streamRoom.data().size()-1);
//         auto key = _keyProvider->getKey(streamRoom.keys(), streamRoomDataEntry.keyId());
//         auto encryptedStreamRoomData = utils::TypedObjectFactory::createObjectFromVar<server::EncryptedStreamRoomDataV4>(streamRoomDataEntry.data());
//         return _streamRoomDataEncryptorV4.decrypt(encryptedStreamRoomData, key.key);
//     } catch (const core::Exception& e) {
//         return DecryptedStreamRoomData({{},{},{},{},.statusCode = e.getCode()});
//     } catch (const privmx::utils::PrivmxException& e) {
//         return DecryptedStreamRoomData({{},{},{},{},.statusCode = core::ExceptionConverter::convert(e).getCode()});
//     } catch (...) {
//         return DecryptedStreamRoomData({{},{},{},{},.statusCode = ENDPOINT_CORE_EXCEPTION_CODE});
//     }
// }

// StreamRoom StreamApiImpl::convertDecryptedStreamRoomDataToStreamRoom(const server::StreamRoomInfo& streamRoomInfo, const DecryptedStreamRoomData& streamRoomData) {
//     std::vector<std::string> users;
//     std::vector<std::string> managers;
//     for (auto x : streamRoomInfo.users()) {
//         users.push_back(x);
//     }
//     for (auto x : streamRoomInfo.managers()) {
//         managers.push_back(x);
//     }

//     return {
//         .contextId = streamRoomInfo.contextId(),
//         .streamRoomId = streamRoomInfo.id(),
//         .createDate = streamRoomInfo.createDate(),
//         .creator = streamRoomInfo.creator(),
//         .lastModificationDate = streamRoomInfo.lastModificationDate(),
//         .lastModifier = streamRoomInfo.lastModifier(),
//         .users = users,
//         .managers = managers,
//         .version = streamRoomInfo.version(),
//         .publicMeta = streamRoomData.publicMeta,
//         .privateMeta = streamRoomData.privateMeta,
//         .policy = core::Factory::parsePolicyServerObject(streamRoomInfo.policy()), 
//         .statusCode = streamRoomData.statusCode
//     };
// }

// StreamRoom StreamApiImpl::decryptAndConvertStreamRoomDataToStreamRoom(const server::StreamRoomInfo& streamRoom) {
//     auto storDdataEntry = streamRoom.data().get(streamRoom.data().size()-1);
//     auto versioned = utils::TypedObjectFactory::createObjectFromVar<dynamic::VersionedData>(storDdataEntry.data());
//     if (!versioned.versionEmpty() && versioned.version() == 4) {
//         return convertDecryptedStreamRoomDataToStreamRoom(streamRoom, decryptStreamRoomV4(streamRoom));
//     }
//     auto e = UnknowStreamRoomFormatException();
//     return StreamRoom{{},{},{},{},{},{},{},{},{},{},{},{}, .statusCode = e.getCode()};
// }

int64_t StreamApiImpl::generateNumericId() {
    return std::rand();
}
