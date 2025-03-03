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

#include "privmx/endpoint/stream/StreamApiLowImpl.hpp"
#include "privmx/endpoint/stream/StreamTypes.hpp"
#include "privmx/endpoint/stream/StreamException.hpp"
#include "privmx/endpoint/stream/DynamicTypes.hpp"


using namespace privmx::endpoint;
using namespace privmx::endpoint::stream;

StreamApiLowImpl::StreamApiLowImpl(
    const std::shared_ptr<event::EventApiImpl>& eventApi,
    const std::shared_ptr<core::ConnectionImpl>& connection,
    const privfs::RpcGateway::Ptr& gateway,
    const privmx::crypto::PrivateKey& userPrivKey,
    const std::shared_ptr<core::KeyProvider>& keyProvider,
    const std::string& host,
    const std::shared_ptr<core::EventMiddleware>& eventMiddleware,
    const std::shared_ptr<core::EventChannelManager>& eventChannelManager
) : _eventApi(eventApi),
    _connection(connection),
    _gateway(gateway),
    _userPrivKey(userPrivKey),
    _keyProvider(keyProvider),
    _host(host),
    _eventMiddleware(eventMiddleware),
    _serverApi(std::make_shared<ServerApi>(gateway)),
    _streamSubscriptionHelper(core::SubscriptionHelper(eventChannelManager, "stream", "streams")) {
        // streamGetTurnCredentials
        auto model = utils::TypedObjectFactory::createNewObject<server::StreamGetTurnCredentialsModel>();
        auto credentials = _serverApi->streamGetTurnCredentials(model).credentials();
        _notificationListenerId = _eventMiddleware->addNotificationEventListener(std::bind(&StreamApiLowImpl::processNotificationEvent, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
        _connectedListenerId = _eventMiddleware->addConnectedEventListener(std::bind(&StreamApiLowImpl::processConnectedEvent, this));
        _disconnectedListenerId = _eventMiddleware->addDisconnectedEventListener(std::bind(&StreamApiLowImpl::processDisconnectedEvent, this));
    }

StreamApiLowImpl::~StreamApiLowImpl() {
    _streamRoomMap.forAll([&]([[maybe_unused]]std::string key,std::shared_ptr<privmx::endpoint::stream::StreamApiLowImpl::StreamRoomData> value) {
        value->streamMap.forAll([&]([[maybe_unused]]int64_t key, std::shared_ptr<StreamData> value) {
            value->webRtc->close();
        });
        value->streamMap.clear();
    });
    _streamRoomMap.clear();
    _eventMiddleware->removeNotificationEventListener(_notificationListenerId);
    _eventMiddleware->removeConnectedEventListener(_connectedListenerId);
    _eventMiddleware->removeDisconnectedEventListener(_disconnectedListenerId);
}

std::vector<TurnCredentials> StreamApiLowImpl::getTurnCredentials() {
    auto model = utils::TypedObjectFactory::createNewObject<server::StreamGetTurnCredentialsModel>();
    auto credentials = _serverApi->streamGetTurnCredentials(model).credentials();
    std::vector<TurnCredentials> result;
    for(auto credential : credentials) {
        result.push_back(TurnCredentials{.url=credential.url(), .username=credential.username(), .password=credential.password(), .expirationTime=credential.expirationTime()});
    }
    return result;
}

void StreamApiLowImpl::processNotificationEvent(const std::string& type, const std::string& channel, const Poco::JSON::Object::Ptr& data) {
    if(_eventApi->isInternalContextEvent(type, channel, data, "StreamKeyManagementEvent")) {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<event::server::ContextCustomEventData>(data);
        auto decryptedData = _eventApi->extractInternalEventData(data);
        auto streamKeyManagementEvent = utils::TypedObjectFactory::createObjectFromVar<dynamic::StreamKeyManagementEvent>(
            privmx::utils::Utils::parseJson(decryptedData.data.stdString())
        );
        auto roomOpt = _streamRoomMap.get(streamKeyManagementEvent.streamRoomId());
        if(roomOpt.has_value()) {
            roomOpt.value()->streamKeyManager->respondToEvent(streamKeyManagementEvent, raw.author().id(), raw.author().pub());
        }
    }
    
}

void StreamApiLowImpl::processConnectedEvent() {

}

void StreamApiLowImpl::processDisconnectedEvent() {

}
// V3 code 

std::shared_ptr<privmx::endpoint::stream::StreamApiLowImpl::StreamRoomData> StreamApiLowImpl::createEmptyStreamRoomData(const std::string& streamRoomId) {
    auto model = privmx::utils::TypedObjectFactory::createNewObject<server::StreamRoomGetModel>();
    model.id(streamRoomId);
    auto streamRoom = _serverApi->streamRoomGet(model).streamRoom();
    std::shared_ptr<StreamRoomData> streamRoomData = std::make_shared<StreamRoomData>(
        std::make_shared<StreamKeyManager>(_eventApi, _keyProvider, _serverApi, _userPrivKey, streamRoomId, streamRoom.contextId()),
        streamRoomId
    );
    _streamRoomMap.set(
        streamRoomId,
        streamRoomData
    );
    return streamRoomData;
}

int64_t StreamApiLowImpl::createStream(const std::string& streamRoomId, int64_t localStreamId, std::shared_ptr<WebRTCInterface> webRtc) {
    auto roomOpt = _streamRoomMap.get(streamRoomId);
    std::shared_ptr<privmx::endpoint::stream::StreamApiLowImpl::StreamRoomData> room;
    if(!roomOpt.has_value()) {
        room = createEmptyStreamRoomData(streamRoomId);
    } else {
        room = roomOpt.value();
    }
    PRIVMX_DEBUG("STREAMS", "API", std::to_string(localStreamId) + ": STREAM Sender")
    _streamIdToRoomId.set(localStreamId, streamRoomId);
    auto keyUpdateId = room->streamKeyManager->addKeyUpdateCallback([webRtc](const std::vector<privmx::endpoint::stream::Key> keys) {
        webRtc->updateKeys(keys);
    });
    room->streamMap.set(
        localStreamId, 
        std::make_shared<StreamData>(
            StreamData{
                .webRtc = webRtc, 
                .sessionId=std::nullopt, 
                .updateId=keyUpdateId
            }
        )
    );
    return localStreamId;
}

// Publishing stream
void StreamApiLowImpl::publishStream(int64_t localStreamId) {
    auto room = getStreamRoomData(localStreamId);
    auto streamData = getStreamData(localStreamId, room);
    std::shared_ptr<WebRTCInterface> webRtc = streamData->webRtc;
    webRtc->updateKeys(room->streamKeyManager->getCurrentWebRtcKeys());
    std::string sdp = webRtc->createOfferAndSetLocalDescription();
    // Publish data on bridge
    auto sessionDescription = utils::TypedObjectFactory::createNewObject<server::SessionDescription>();
    sessionDescription.sdp(sdp);
    sessionDescription.type("offer");
    auto model = utils::TypedObjectFactory::createNewObject<server::StreamPublishModel>();
    model.streamRoomId(room->id); //TODO
    model.offer(sessionDescription);
    auto result = _serverApi->streamPublish(model);
    streamData->sessionId = result.sessionId();
    // Set remote description
    webRtc->setAnswerAndSetRemoteDescription(result.answer().sdp(), result.answer().type());
}

// Joining to Stream
int64_t StreamApiLowImpl::joinStream(const std::string& streamRoomId, const std::vector<int64_t>& streamsId, [[maybe_unused]] const Settings& settings, int64_t localStreamId, std::shared_ptr<WebRTCInterface> webRtc) {
    auto roomOpt = _streamRoomMap.get(streamRoomId);
    std::shared_ptr<privmx::endpoint::stream::StreamApiLowImpl::StreamRoomData> room;
    if(!roomOpt.has_value()) {
        room = createEmptyStreamRoomData(streamRoomId);
    } else {
        room = roomOpt.value();
    }
    PRIVMX_DEBUG("STREAMS", "API", std::to_string(localStreamId) + ": STREAM Receiver")
    _streamIdToRoomId.set(localStreamId, streamRoomId);
    // Get data from bridge
    auto streamJoinModel = utils::TypedObjectFactory::createNewObject<server::StreamJoinModel>();
    streamJoinModel.streamIds(utils::TypedObjectFactory::createNewList<int64_t>());
    for(size_t i = 0; i < streamsId.size(); i++) {
        streamJoinModel.streamIds().add(streamsId[i]);
    }
    streamJoinModel.streamRoomId(streamRoomId);
    auto streamJoinResult = _serverApi->streamJoin(streamJoinModel);
    // creating peerConnectio

    auto keyUpdateId = room->streamKeyManager->addKeyUpdateCallback([webRtc](const std::vector<privmx::endpoint::stream::Key> keys) {
        webRtc->updateKeys(keys);
    });
    room->streamMap.set(
        localStreamId, 
        std::make_shared<StreamData>(
            StreamData{
                .webRtc = webRtc,
                .sessionId = streamJoinResult.sessionId(),
                .updateId = keyUpdateId
            }
        )
    );
    std::string sdp = webRtc->createAnswerAndSetDescriptions(streamJoinResult.offer().sdp(), streamJoinResult.offer().type());
    auto sessionDescription = utils::TypedObjectFactory::createNewObject<server::SessionDescription>();
    sessionDescription.sdp(sdp);
    sessionDescription.type("answer");
    auto model = utils::TypedObjectFactory::createNewObject<server::StreamAcceptOfferModel>();
    model.sessionId(streamJoinResult.sessionId());
    model.answer(sessionDescription);
    _serverApi->streamAcceptOffer(model);
    
    // get Room for contextId
    auto modelGetRoom = privmx::utils::TypedObjectFactory::createNewObject<server::StreamRoomGetModel>();
    modelGetRoom.id(streamRoomId);
    auto streamRoom = _serverApi->streamRoomGet(modelGetRoom).streamRoom(); 
    // get Streams for userId
    auto modelStreams = privmx::utils::TypedObjectFactory::createNewObject<server::StreamListModel>();
    modelStreams.streamRoomId(streamRoomId);
    auto streamsList = _serverApi->streamList(modelStreams).list();
    // get all users for pubKey
    std::vector<core::UserInfo> allUsersList = _connection->getContextUsers(streamRoom.contextId()); 
    std::vector<std::string> usersIds;
    for(auto s: streamsList) {
        if ( std::find(streamsId.begin(), streamsId.end(), s.streamId()) != streamsId.end() ) {
            usersIds.push_back(s.userId());
        }
    }
    std::vector<core::UserWithPubKey> toSend;
    for(auto userInfo: allUsersList) {
        if(std::find(usersIds.begin(), usersIds.end(), userInfo.user.userId) != usersIds.end() ) {
            toSend.push_back(userInfo.user);
        }
    }
    room->streamKeyManager->requestKey(toSend);
    return localStreamId;
}

std::vector<Stream> StreamApiLowImpl::listStreams(const std::string& streamRoomId) {
    auto model = privmx::utils::TypedObjectFactory::createNewObject<server::StreamListModel>();
    model.streamRoomId(streamRoomId);
    auto streamList = _serverApi->streamList(model).list();
    std::vector<Stream> result;
    for(auto stream: streamList) {
        result.push_back(Stream{.streamId=stream.streamId(),.userId=stream.userId()});
    }
    return result;
}

std::string StreamApiLowImpl::createStreamRoom(
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

void StreamApiLowImpl::updateStreamRoom(
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

core::PagingList<StreamRoom> StreamApiLowImpl::listStreamRooms(const std::string& contextId, const core::PagingQuery& query) {
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

StreamRoom StreamApiLowImpl::getStreamRoom(const std::string& streamRoomId) {
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

void StreamApiLowImpl::deleteStreamRoom(const std::string& streamRoomId) {
    PRIVMX_DEBUG_TIME_START(PlatformStream, deleteStreamRoom)
    auto model = utils::TypedObjectFactory::createNewObject<server::StreamRoomDeleteModel>();
    model.id(streamRoomId);
    _serverApi->streamRoomDelete(model);
    PRIVMX_DEBUG_TIME_STOP(PlatformStream, deleteStreamRoom)
}

DecryptedStreamRoomData StreamApiLowImpl::decryptStreamRoomV4(const server::StreamRoomInfo& streamRoom) {
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

StreamRoom StreamApiLowImpl::convertDecryptedStreamRoomDataToStreamRoom(const server::StreamRoomInfo& streamRoomInfo, const DecryptedStreamRoomData& streamRoomData) {
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

StreamRoom StreamApiLowImpl::decryptAndConvertStreamRoomDataToStreamRoom(const server::StreamRoomInfo& streamRoom) {
    auto storDdataEntry = streamRoom.data().get(streamRoom.data().size()-1);
    auto versioned = utils::TypedObjectFactory::createObjectFromVar<dynamic::VersionedData>(storDdataEntry.data());
    if (!versioned.versionEmpty() && versioned.version() == 4) {
        return convertDecryptedStreamRoomDataToStreamRoom(streamRoom, decryptStreamRoomV4(streamRoom));
    }
    auto e = UnknowStreamRoomFormatException();
    return StreamRoom{{},{},{},{},{},{},{},{},{},{},{},{}, .statusCode = e.getCode()};
}

int64_t StreamApiLowImpl::generateNumericId() {
    return std::rand();
}

privmx::utils::List<std::string> StreamApiLowImpl::mapUsers(const std::vector<core::UserWithPubKey>& users) {
    auto result = privmx::utils::TypedObjectFactory::createNewList<std::string>();
    for (auto user : users) {
        result.add(user.userId);
    }
    return result;
}

void StreamApiLowImpl::unpublishStream(int64_t localStreamId) {
    auto room = getStreamRoomData(localStreamId);
    auto streamData = getStreamData(localStreamId, room);
    if(streamData->sessionId.has_value()) {
        server::StreamUnpublishModel model = privmx::utils::TypedObjectFactory::createNewObject<server::StreamUnpublishModel>();
        model.sessionId(streamData->sessionId.value());
        _serverApi->streamUnpublish(model);
    }
    room->streamKeyManager->removeKeyUpdateCallback(streamData->updateId);
    streamData->webRtc->close();
    room->streamMap.erase(localStreamId);
    if(room->streamMap.size() == 0) {
        _streamIdToRoomId.erase(localStreamId);
        _streamRoomMap.erase(room->id);
    }
}

void StreamApiLowImpl::leaveStream(int64_t localStreamId) {
    auto room = getStreamRoomData(localStreamId);
    auto streamData = getStreamData(localStreamId, room);
    if(streamData->sessionId.has_value()) {
        server::StreamLeaveModel model = privmx::utils::TypedObjectFactory::createNewObject<server::StreamLeaveModel>();
        model.sessionId(streamData->sessionId.value());
        _serverApi->streamLeave(model);
    }
    room->streamKeyManager->removeKeyUpdateCallback(streamData->updateId);
    streamData->webRtc->close();
    room->streamMap.erase(localStreamId);
    if(room->streamMap.size() == 0) {
        _streamIdToRoomId.erase(localStreamId);
        _streamRoomMap.erase(room->id);
    }
}

std::shared_ptr<StreamApiLowImpl::StreamRoomData> StreamApiLowImpl::getStreamRoomData(const std::string& streamRoomId) {
    auto room = _streamRoomMap.get(streamRoomId);
    if(!room.has_value()) {
        throw StreamCacheException();
    }
    return room.value();
}

std::shared_ptr<StreamApiLowImpl::StreamRoomData> StreamApiLowImpl::getStreamRoomData(int64_t localStreamId) {
    auto streamRoomId = _streamIdToRoomId.get(localStreamId);
    if(!streamRoomId.has_value()) {
        throw IncorrectStreamIdException();
    }
    return getStreamRoomData(streamRoomId.value());
}

std::shared_ptr<StreamApiLowImpl::StreamData> StreamApiLowImpl::getStreamData(int64_t localStreamId, std::shared_ptr<StreamRoomData> room) {
    auto streamData = room->streamMap.get(localStreamId);
    if(!streamData.has_value()) {
        throw IncorrectStreamIdException();
    }
    return streamData.value();
}

void StreamApiLowImpl::keyManagement(const std::string& streamRoomId, bool disable) {
    auto room = _streamRoomMap.get(streamRoomId);
    if(room.has_value())
        room.value()->streamKeyManager->keyManagement(disable);
}