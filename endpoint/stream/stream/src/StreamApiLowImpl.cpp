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
#include <privmx/endpoint/core/TimestampValidator.hpp>

#include "privmx/endpoint/stream/StreamApiLowImpl.hpp"
#include "privmx/endpoint/stream/StreamTypes.hpp"
#include "privmx/endpoint/stream/StreamException.hpp"
#include "privmx/endpoint/stream/DynamicTypes.hpp"
#include "privmx/endpoint/stream/Events.hpp"
#include "privmx/endpoint/core/UsersKeysResolver.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::stream;

StreamApiLowImpl::StreamApiLowImpl(
    const std::shared_ptr<event::EventApiImpl>& eventApi,
    const core::Connection& connection,
    const privfs::RpcGateway::Ptr& gateway,
    const privmx::crypto::PrivateKey& userPrivKey,
    const std::shared_ptr<core::KeyProvider>& keyProvider,
    const std::string& host,
    const std::shared_ptr<core::EventMiddleware>& eventMiddleware,
    const std::shared_ptr<core::EventChannelManager>& eventChannelManager
) : ModuleBaseApi(userPrivKey, keyProvider, host, eventMiddleware, eventChannelManager, connection),
     _eventApi(eventApi),
    _connection(connection.getImpl()),
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
        _notificationListenerId = _eventMiddleware->addNotificationEventListener(std::bind(&StreamApiLowImpl::processNotificationEvent, this, std::placeholders::_1, std::placeholders::_2));
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

void StreamApiLowImpl::processNotificationEvent(const std::string& type, const core::NotificationEvent& notification) {
    std::cerr << "new event: " << type << std::endl;
    if (type == "janus") {
        std::cerr << privmx::utils::Utils::stringifyVar(notification.data, true) << std::endl;
    }
    Poco::JSON::Object::Ptr data = notification.data.extract<Poco::JSON::Object::Ptr>();
    std::cerr << "before check: " << privmx::utils::Utils::stringifyVar(data) << std::endl;
    try {
        isInternalJanusEvent(type, data);
        std::cerr << "after check" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error in isInternalJanusEvent(): " << e.what() << std::endl;
    }


    if(_eventApi->isInternalContextEvent(type, notification.subscriptions, data, "StreamKeyManagementEvent")) {
        std::cerr << __LINE__ << std::endl;
        auto raw = utils::TypedObjectFactory::createObjectFromVar<event::server::ContextCustomEventData>(data);
        auto decryptedData = _eventApi->extractInternalEventData(data);
        auto streamKeyManagementEvent = utils::TypedObjectFactory::createObjectFromVar<dynamic::StreamKeyManagementEvent>(
            privmx::utils::Utils::parseJson(decryptedData.data.stdString())
        );
        auto roomOpt = _streamRoomMap.get(streamKeyManagementEvent.streamRoomId());
        if(roomOpt.has_value()) {
            roomOpt.value()->streamKeyManager->respondToEvent(streamKeyManagementEvent, raw.author().id(), raw.author().pub());
        }
        return;
    }

    // PRIVMX_DEBUG("StreamApiLowImpl", "processNotificationEvent", "event_type: " + type + "\n" + privmx::utils::Utils::stringifyVar(notification.data, true))
    if(!_streamSubscriptionHelper.hasSubscription(notification.subscriptions) && !isInternalJanusEvent(type, data)) {
        std::cerr << __LINE__ << std::endl;
        return;
    }
    if (isInternalJanusEvent(type, data)) {
        auto janusEventData = data->getObject("data");
        processJanusEvent(janusEventData);
        return;
    }
    
    if (type == "streamRoomCreated") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::StreamRoomInfo>(data);
        auto data = decryptAndConvertStreamRoomDataToStreamRoom(raw); 
        std::shared_ptr<StreamRoomCreatedEvent> event(new StreamRoomCreatedEvent());
        event->channel = "stream";
        event->data = data;
        _eventMiddleware->emitApiEvent(event);
    } else if (type == "streamRoomUpdated") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::StreamRoomInfo>(data);
        auto data = decryptAndConvertStreamRoomDataToStreamRoom(raw); 
        std::shared_ptr<StreamRoomUpdatedEvent> event(new StreamRoomUpdatedEvent());
        event->channel = "stream";
        event->data = data;
        _eventMiddleware->emitApiEvent(event);
    } else if (type == "streamRoomDeleted") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::StreamRoomDeletedEventData>(data);
        std::shared_ptr<StreamRoomDeletedEvent> event(new StreamRoomDeletedEvent());
        event->channel = "stream";
        event->data = StreamRoomDeletedEventData{.streamRoomId=raw.streamRoomId()};
        _eventMiddleware->emitApiEvent(event);
    } else if (type == "streamPublished" || type == "streamJoined" || type == "streamUnpublished" || type == "streamLeft" ) {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::StreamEventData>(data);
        std::vector<int64_t> streamIds;
        for(auto i : raw.streamIds()) streamIds.push_back(i);
        auto eventData = StreamEventData{.streamRoomId=raw.streamRoomId(), .streamIds=streamIds, .userId=raw.userId()};
        if(type == "streamPublished") {
            std::shared_ptr<StreamPublishedEvent> event(new StreamPublishedEvent());
            event->channel = "stream";
            event->data = eventData;
            _eventMiddleware->emitApiEvent(event);
        } else if(type == "streamJoined") {
            std::shared_ptr<StreamJoinedEvent> event(new StreamJoinedEvent());
            event->channel = "stream";
            event->data = eventData;
            _eventMiddleware->emitApiEvent(event);
        } else if(type == "streamUnpublished") {
            std::shared_ptr<StreamUnpublishedEvent> event(new StreamUnpublishedEvent());
            event->channel = "stream";
            event->data = eventData;
            _eventMiddleware->emitApiEvent(event);
        } else if(type == "streamLeft") {
            std::shared_ptr<StreamLeftEvent> event(new StreamLeftEvent());
            event->channel = "stream";
            event->data = eventData;
            _eventMiddleware->emitApiEvent(event);
        }
    }
}

bool StreamApiLowImpl::isInternalJanusEvent(const std::string& type, const Poco::JSON::Object::Ptr event) {
    return type == "janus" 
    && event->has("data") 
    && event->getObject("data")->has("janus");
}

void StreamApiLowImpl::processJanusEvent(const Poco::JSON::Object::Ptr data) {
    std::cerr << "=========> PROCESSING JANUS EVENT <==================" << std::endl;
    auto janusPluginEvent = utils::TypedObjectFactory::createObjectFromVar<server::JanusPluginEvent>(data);
    PRIVMX_DEBUG("StreamApiLowImpl", "processJanusEvent", "janusPluginEvent :\n" + privmx::utils::Utils::stringifyVar(janusPluginEvent, true));
    
    auto localStreamId = _sessionIdToStreamId.get(janusPluginEvent.session_id());
    // if stream is about me
    if(localStreamId.has_value() && _streamIdToRoomId.has(localStreamId.value())) {
        //if streamId exist that mens stream and room exist
        auto room = getStreamRoomData(localStreamId.value());
        auto streamData = getStreamData(localStreamId.value(), room);
    
        if(!janusPluginEvent.plugindataEmpty() && janusPluginEvent.plugindata().pluginOpt("") == "janus.plugin.videoroom") {
            auto janusVideoRoom = utils::TypedObjectFactory::createObjectFromVar<server::JanusVideoRoom>(janusPluginEvent.plugindata().data());
            if(janusVideoRoom.videoroomOpt("") == "updated") {
                auto janusVideoRoomUpdated = utils::TypedObjectFactory::createObjectFromVar<server::JanusVideoRoomUpdated>(janusVideoRoom);
                std::optional<server::JanusJSEP> jsep = std::nullopt;
                if (!janusPluginEvent.jsepEmpty()) {
                    jsep = janusPluginEvent.jsep();
                }
                std::cerr << __LINE__ << std::endl;
                onVideoRoomUpdate(janusPluginEvent.session_id(), janusVideoRoomUpdated, streamData, jsep);
            }
        }
    }
}

void StreamApiLowImpl::onVideoRoomUpdate(const int64_t session_id, server::JanusVideoRoomUpdated updateEvent, std::shared_ptr<StreamData> streamData, const std::optional<server::JanusJSEP>& jsep) {
    PRIVMX_DEBUG("StreamApiLowImpl", "onVideoRoomUpdate", "session_id :" + std::to_string(session_id));
    if (jsep.has_value() && !jsep.value().sdpEmpty() && !jsep.value().typeEmpty()) {
        auto t = std::thread([&](const int64_t session_id_copy, server::JanusVideoRoomUpdated updateEvent_copy, std::shared_ptr<StreamData> streamData_copy, server::JanusJSEP jsep_copy) {
            std::cerr << __LINE__ << std::endl;
            auto sdp = streamData_copy->webRtc->createAnswerAndSetDescriptions(jsep_copy.sdp(), jsep_copy.type());
            auto janusJSEP = utils::TypedObjectFactory::createNewObject<server::JanusJSEP>();
            janusJSEP.sdp(sdp);
            janusJSEP.type("answer");
            auto options = utils::Utils::parseJsonObject("{}");
            options->set("restart", true);
            options->set("jsep", janusJSEP);
            auto model = utils::TypedObjectFactory::createNewObject<server::StreamReconfigureModel>();
            
            model.sessionId(session_id_copy); //TODO
            model.options(options);
            PRIVMX_DEBUG("StreamApiLowImpl", "onVideoRoomUpdate", "_serverApi->streamReconfigure: \n" + privmx::utils::Utils::stringifyVar(model, true));
            _serverApi->streamReconfigure(model);
            PRIVMX_DEBUG("StreamApiLowImpl", "onVideoRoomUpdate", "_serverApi->streamReconfigure Done");

            // auto sessionDescription = utils::TypedObjectFactory::createNewObject<server::SessionDescription>();
            // sessionDescription.sdp(sdp);
            // sessionDescription.type("answer");
            // auto model = utils::TypedObjectFactory::createNewObject<server::StreamAcceptOfferModel>();
            // model.sessionId(session_id);
            // model.answer(sessionDescription);
            // PRIVMX_DEBUG("StreamApiLowImpl", "onVideoRoomUpdate", "_serverApi->streamAcceptOffer");
            // _serverApi->streamAcceptOffer(model);
            // PRIVMX_DEBUG("StreamApiLowImpl", "onVideoRoomUpdate", "_serverApi->streamAcceptOffer Done");
            return;
        }, session_id, updateEvent, streamData, jsep.value());
        t.detach();
    } else {
        PRIVMX_DEBUG("StreamApiLowImpl", "onVideoRoomUpdate", "Done");
        std::cerr << "onVideoRoomUpdate (but without jsep)" << std::endl;
    }
    PRIVMX_DEBUG("StreamApiLowImpl", "onVideoRoomUpdate", "Done");
    // TODO: update list of available streams and emit user event about update
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
    PRIVMX_DEBUG("STREAMS", "joinStream", "SessionId: " + std::to_string(streamJoinResult.sessionIdOpt(0)))
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
    _sessionIdToStreamId.set(streamJoinResult.sessionId(), localStreamId);
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
    PRIVMX_DEBUG_TIME_START(PlatformStreamRoom, _createStreamRoomEx)
    auto streamRoomKey = _keyProvider->generateKey();
    std::string resourceId = core::EndpointUtils::generateId();
    auto streamRoomDIO = _connection->createDIO(
        contextId,
        resourceId
    );
    auto streamRoomSecret = _keyProvider->generateSecret();

    core::ModuleDataToEncryptV5 streamRoomDataToEncrypt {
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .internalMeta = core::ModuleInternalMetaV5{.secret=streamRoomSecret, .resourceId=resourceId, .randomId=streamRoomDIO.randomId},
        .dio = streamRoomDIO
    };
    auto createStreamRoomModel = utils::TypedObjectFactory::createNewObject<server::StreamRoomCreateModel>();
    createStreamRoomModel.resourceId(resourceId);
    createStreamRoomModel.contextId(contextId);
    createStreamRoomModel.keyId(streamRoomKey.id);
    createStreamRoomModel.data(_streamRoomDataEncryptorV5.encrypt(streamRoomDataToEncrypt, _userPrivKey, streamRoomKey.key).asVar());
    auto allUsers = core::EndpointUtils::uniqueListUserWithPubKey(users, managers);
    createStreamRoomModel.keys(
        _keyProvider->prepareKeysList(
            allUsers, 
            streamRoomKey, 
            streamRoomDIO,
            {.contextId=contextId, .resourceId=resourceId},
            streamRoomSecret
        )
    );

    createStreamRoomModel.users(mapUsers(users));
    createStreamRoomModel.managers(mapUsers(managers));
    if (policies.has_value()) {
        createStreamRoomModel.policy(privmx::endpoint::core::Factory::createPolicyServerObject(policies.value()));
    }
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStreamRoom, _createStreamRoomEx, data encrypted)
    auto result = _serverApi->streamRoomCreate(createStreamRoomModel);
    PRIVMX_DEBUG_TIME_STOP(PlatformStreamRoom, _createStreamRoomEx, data send)
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
    auto currentStreamRoomEntry = currentStreamRoom.data().get(currentStreamRoom.data().size()-1);
    auto currentStreamRoomResourceId = currentStreamRoom.resourceIdOpt(core::EndpointUtils::generateId());
    auto location {getModuleEncKeyLocation(currentStreamRoom, currentStreamRoomResourceId)};
    auto streamRoomKeys {getAndValidateModuleKeys(currentStreamRoom, currentStreamRoomResourceId)};
    auto currentStreamRoomKey {findEncKeyByKeyId(streamRoomKeys, currentStreamRoomEntry.keyId())};
    auto streamRoomInternalMeta = extractAndDecryptModuleInternalMeta(currentStreamRoomEntry, currentStreamRoomKey);

    auto usersKeysResolver {core::UsersKeysResolver::create(currentStreamRoom, users, managers, forceGenerateNewKey, currentStreamRoomKey)};

    if(!_keyProvider->verifyKeysSecret(streamRoomKeys, location, streamRoomInternalMeta.secret)) {
        throw StreamRoomEncryptionKeyValidationException();
    }
    // setting streamRoom Key adding new users
    core::EncKey streamRoomKey = currentStreamRoomKey;
    core::DataIntegrityObject updateStreamRoomDio = _connection->createDIO(currentStreamRoom.contextId(), currentStreamRoomResourceId);
    privmx::utils::List<core::server::KeyEntrySet> keys = utils::TypedObjectFactory::createNewList<core::server::KeyEntrySet>();
    if(usersKeysResolver->doNeedNewKey()) {
        streamRoomKey = _keyProvider->generateKey();
        keys = _keyProvider->prepareKeysList(
            usersKeysResolver->getNewUsers(), 
            streamRoomKey, 
            updateStreamRoomDio,
            location,
            streamRoomInternalMeta.secret
        );
    }

    auto usersToAddMissingKey {usersKeysResolver->getUsersToAddKey()};
    if(usersToAddMissingKey.size() > 0) {
        auto tmp = _keyProvider->prepareMissingKeysForNewUsers(
            streamRoomKeys,
            usersToAddMissingKey, 
            updateStreamRoomDio, 
            location,
            streamRoomInternalMeta.secret
        );
        for(auto t: tmp) keys.add(t);
    }
    auto model = utils::TypedObjectFactory::createNewObject<server::StreamRoomUpdateModel>();
    auto usersList = utils::TypedObjectFactory::createNewList<std::string>();
    for (auto user: users) {
        usersList.add(user.userId);
    }
    auto managersList = utils::TypedObjectFactory::createNewList<std::string>();
    for (auto x: managers) {
        managersList.add(x.userId);
    }
    model.id(streamRoomId);
    model.resourceId(currentStreamRoomResourceId);
    model.keyId(streamRoomKey.id);
    model.keys(keys);
    model.users(usersList);
    model.managers(managersList);
    model.version(version);
    model.force(force);
    if (policies.has_value()) {
        model.policy(privmx::endpoint::core::Factory::createPolicyServerObject(policies.value()));
    }
    core::ModuleDataToEncryptV5 streamRoomDataToEncrypt {
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .internalMeta = core::ModuleInternalMetaV5{.secret=streamRoomInternalMeta.secret, .resourceId=currentStreamRoomResourceId, .randomId=updateStreamRoomDio.randomId},
        .dio = updateStreamRoomDio
    };
    model.data(_streamRoomDataEncryptorV5.encrypt(streamRoomDataToEncrypt, _userPrivKey, streamRoomKey.key).asVar());

    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStream, updateStreamRoom, data encrypted)
    _serverApi->streamRoomUpdate(model);
    PRIVMX_DEBUG_TIME_STOP(PlatformStream, updateStreamRoom, data send)
}

core::PagingList<StreamRoom> StreamApiLowImpl::listStreamRooms(const std::string& contextId, const core::PagingQuery& query) {
    PRIVMX_DEBUG_TIME_START(PlatformStream, listStreamRooms)
    auto model = utils::TypedObjectFactory::createNewObject<server::StreamRoomListModel>();
    model.contextId(contextId);
    core::ListQueryMapper::map(model, query);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStream, listStreamRooms, getting streamRoomList)
    auto streamRoomsList = _serverApi->streamRoomList(model);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStream, listStreamRooms, data send)
    std::vector<StreamRoom> streamRooms;
    for (size_t i = 0; i < streamRoomsList.list().size(); i++) {
        auto streamRoom = streamRoomsList.list().get(i);
        auto statusCode = validateStreamRoomDataIntegrity(streamRoom);
        streamRooms.push_back(convertServerStreamRoomToLibStreamRoom(streamRoom,{},{},statusCode));
        if(statusCode != 0) {
            streamRoomsList.list().remove(i);
            i--;
        }
    }
    auto tmp = decryptAndConvertStreamRoomsDataToStreamRooms(streamRoomsList.list());
    for(size_t j = 0, i = 0; i < streamRooms.size(); i++) {
        if(streamRooms[i].statusCode == 0) {
            streamRooms[i] = tmp[j];
            j++;
        }
    }
    PRIVMX_DEBUG_TIME_STOP(PlatformStream, listStreamRooms, data decrypted)
    return core::PagingList<StreamRoom>({
        .totalAvailable = streamRoomsList.count(),
        .readItems = streamRooms
    });
}

StreamRoom StreamApiLowImpl::getStreamRoom(const std::string& streamRoomId) {
    PRIVMX_DEBUG_TIME_START(PlatformStream, getStreamRoom)
    auto params = utils::TypedObjectFactory::createNewObject<server::StreamRoomGetModel>();
    params.id(streamRoomId);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStream,getStreamRoom, getting streamRoom)
    auto streamRoom = _serverApi->streamRoomGet(params).streamRoom();
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStream, getStreamRoom, data send)
    auto statusCode = validateStreamRoomDataIntegrity(streamRoom);
    if(statusCode != 0) {
        return convertServerStreamRoomToLibStreamRoom(streamRoom,{},{},statusCode);
    }
    auto result = decryptAndConvertStreamRoomDataToStreamRoom(streamRoom);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStream, getStreamRoom, data decrypted)
    return result;
}

void StreamApiLowImpl::deleteStreamRoom(const std::string& streamRoomId) {
    PRIVMX_DEBUG_TIME_START(PlatformStream, deleteStreamRoom)
    auto model = utils::TypedObjectFactory::createNewObject<server::StreamRoomDeleteModel>();
    model.id(streamRoomId);
    _serverApi->streamRoomDelete(model);
    PRIVMX_DEBUG_TIME_STOP(PlatformStream, deleteStreamRoom)
}

StreamRoom StreamApiLowImpl::convertServerStreamRoomToLibStreamRoom(
    server::StreamRoomInfo streamRoomInfo,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const int64_t& statusCode,
    const int64_t& schemaVersion
) {
    std::vector<std::string> users;
    std::vector<std::string> managers;
    if(!streamRoomInfo.usersEmpty()) {
        for (auto x : streamRoomInfo.users()) {
            users.push_back(x);
        }
    }
    if(!streamRoomInfo.managersEmpty()) {
        for (auto x : streamRoomInfo.managers()) {
            managers.push_back(x);
        }
    }
    return StreamRoom{
        .contextId = streamRoomInfo.contextIdOpt(""),
        .streamRoomId = streamRoomInfo.idOpt(""),
        .createDate = streamRoomInfo.createDateOpt(0),
        .creator = streamRoomInfo.creatorOpt(""),
        .lastModificationDate = streamRoomInfo.lastModificationDateOpt(0),
        .lastModifier = streamRoomInfo.lastModifierOpt(""),
        .users = users,
        .managers = managers,
        .version = streamRoomInfo.versionOpt(0),
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .policy = core::Factory::parsePolicyServerObject(streamRoomInfo.policyOpt(Poco::JSON::Object::Ptr(new Poco::JSON::Object))), 
        .statusCode = statusCode,
        .schemaVersion = schemaVersion
    };
}

StreamRoom StreamApiLowImpl::convertDecryptedStreamRoomDataV5ToStreamRoom(server::StreamRoomInfo streamRoomInfo, const core::DecryptedModuleDataV5& streamRoomData) {  
    return convertServerStreamRoomToLibStreamRoom(
        streamRoomInfo, 
        streamRoomData.publicMeta, 
        streamRoomData.privateMeta, 
        streamRoomData.statusCode, 
        StreamRoomDataSchema::Version::VERSION_5
    );
}

StreamRoomDataSchema::Version StreamApiLowImpl::getStreamRoomEntryDataStructureVersion(server::StreamRoomDataEntry streamRoomEntry) {
    if (streamRoomEntry.data().type() == typeid(Poco::JSON::Object::Ptr)) {
        auto versioned = utils::TypedObjectFactory::createObjectFromVar<core::dynamic::VersionedData>(streamRoomEntry.data());
        auto version = versioned.versionOpt(core::ModuleDataSchema::Version::UNKNOWN);
        switch (version) {
            case core::ModuleDataSchema::Version::VERSION_5:
                return StreamRoomDataSchema::Version::VERSION_5;
            default:
                return StreamRoomDataSchema::Version::UNKNOWN;
        }
    }
    return StreamRoomDataSchema::Version::UNKNOWN;
}

std::tuple<StreamRoom, core::DataIntegrityObject> StreamApiLowImpl::decryptAndConvertStreamRoomDataToStreamRoom(server::StreamRoomInfo streamRoom, server::StreamRoomDataEntry streamRoomEntry, const core::DecryptedEncKey& encKey) {
    switch (getStreamRoomEntryDataStructureVersion(streamRoomEntry)) {
        case StreamRoomDataSchema::Version::UNKNOWN: {
            auto e = UnknowStreamRoomFormatException();
            return std::make_tuple(convertServerStreamRoomToLibStreamRoom(streamRoom, {}, {}, e.getCode()), core::DataIntegrityObject());
        }
        case StreamRoomDataSchema::Version::VERSION_5: {
            auto decryptedStreamRoomData = decryptModuleDataV5(streamRoomEntry, encKey);
            return std::make_tuple(convertDecryptedStreamRoomDataV5ToStreamRoom(streamRoom, decryptedStreamRoomData), decryptedStreamRoomData.dio);
        }            
    }
    auto e = UnknowStreamRoomFormatException();
    return std::make_tuple(convertServerStreamRoomToLibStreamRoom(streamRoom, {}, {}, e.getCode()), core::DataIntegrityObject());
}

std::vector<StreamRoom> StreamApiLowImpl::decryptAndConvertStreamRoomsDataToStreamRooms(privmx::utils::List<server::StreamRoomInfo> streamRooms) {
    std::vector<StreamRoom> result;
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    //create request to KeyProvider for keys
    for (size_t i = 0; i < streamRooms.size(); i++) {
        auto streamRoom = streamRooms.get(i);
        core::EncKeyLocation location{.contextId=streamRoom.contextId(), .resourceId=streamRoom.resourceIdOpt("")};
        auto streamRoom_data_entry = streamRoom.data().get(streamRoom.data().size()-1);
        keyProviderRequest.addOne(streamRoom.keys(), streamRoom_data_entry.keyId(), location);
    }
    //send request to KeyProvider
    auto streamRoomsKeys {_keyProvider->getKeysAndVerify(keyProviderRequest)};
    std::vector<core::DataIntegrityObject> streamRoomsDIO;
    std::map<std::string, bool> duplication_check;
    for (auto streamRoom: streamRooms) {
        try {
            auto tmp = decryptAndConvertStreamRoomDataToStreamRoom(
                streamRoom, 
                streamRoom.data().get(streamRoom.data().size()-1), 
                streamRoomsKeys.at(core::EncKeyLocation{.contextId=streamRoom.contextId(), .resourceId=streamRoom.resourceIdOpt("")}).at(streamRoom.data().get(streamRoom.data().size()-1).keyId())
            );
            result.push_back(std::get<0>(tmp));
            auto streamRoomDIO = std::get<1>(tmp);
            streamRoomsDIO.push_back(streamRoomDIO);
            //find duplication
            std::string fullRandomId = streamRoomDIO.randomId + "-" + std::to_string(streamRoomDIO.timestamp);
            if(duplication_check.find(fullRandomId) == duplication_check.end()) {
                duplication_check.insert(std::make_pair(fullRandomId, true));
            } else {
                result[result.size()-1].statusCode = core::DataIntegrityObjectDuplicatedException().getCode();
            }
        } catch (const core::Exception& e) {
            result.push_back(convertServerStreamRoomToLibStreamRoom(streamRoom, {}, {}, e.getCode()));
            streamRoomsDIO.push_back(core::DataIntegrityObject{});
        }
    }
    std::vector<core::VerificationRequest> verifierInput {};
    for (size_t i = 0; i < result.size(); i++) {
        if(result[i].statusCode == 0) {
            verifierInput.push_back(core::VerificationRequest{
                .contextId = result[i].contextId,
                .senderId = result[i].lastModifier,
                .senderPubKey = streamRoomsDIO[i].creatorPubKey,
                .date = result[i].lastModificationDate,
                .bridgeIdentity = streamRoomsDIO[i].bridgeIdentity
            });
        }
    }
    std::vector<bool> verified;
    try {
        verified =_connection->getUserVerifier()->verify(verifierInput);
    } catch (...) {
        throw core::UserVerificationMethodUnhandledException();
    }
    for (size_t j = 0, i = 0; i < result.size(); i++) {
        if(result[i].statusCode == 0) {
            result[i].statusCode = verified[j] ? 0 : core::ExceptionConverter::getCodeOfUserVerificationFailureException();
            j++;
        }
    }
    return result;
}

StreamRoom StreamApiLowImpl::decryptAndConvertStreamRoomDataToStreamRoom(server::StreamRoomInfo streamRoom) {
    auto streamRoom_data_entry = streamRoom.data().get(streamRoom.data().size()-1);
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    core::EncKeyLocation location{.contextId=streamRoom.contextId(), .resourceId=streamRoom.resourceIdOpt("")};
    keyProviderRequest.addOne(streamRoom.keys(), streamRoom_data_entry.keyId(), location);
    auto key = _keyProvider->getKeysAndVerify(keyProviderRequest).at(location).at(streamRoom_data_entry.keyId());
    StreamRoom result;
    core::DataIntegrityObject streamRoomDIO;
    std::tie(result, streamRoomDIO) = decryptAndConvertStreamRoomDataToStreamRoom(streamRoom, streamRoom_data_entry, key);
    if(result.statusCode != 0) return result;
    std::vector<core::VerificationRequest> verifierInput {};
    verifierInput.push_back(core::VerificationRequest{
        .contextId = result.contextId,
        .senderId = result.lastModifier,
        .senderPubKey = streamRoomDIO.creatorPubKey,
        .date = result.lastModificationDate,
        .bridgeIdentity = streamRoomDIO.bridgeIdentity
    });
    std::vector<bool> verified;
    try {
        verified =_connection->getUserVerifier()->verify(verifierInput);
    } catch (...) {
        throw core::UserVerificationMethodUnhandledException();
    }
    result.statusCode = verified[0] ? 0 : core::ExceptionConverter::getCodeOfUserVerificationFailureException();
    return result;
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
    removeStream(room, streamData, localStreamId);
}

void StreamApiLowImpl::leaveStream(int64_t localStreamId) {
    auto room = getStreamRoomData(localStreamId);
    auto streamData = getStreamData(localStreamId, room);
    if(streamData->sessionId.has_value()) {
        server::StreamLeaveModel model = privmx::utils::TypedObjectFactory::createNewObject<server::StreamLeaveModel>();
        model.sessionId(streamData->sessionId.value());
        _serverApi->streamLeave(model);
    }
    removeStream(room, streamData, localStreamId);
}

void StreamApiLowImpl::removeStream(std::shared_ptr<StreamRoomData> room, std::shared_ptr<StreamData> streamData, int64_t localStreamId) {
    room->streamKeyManager->removeKeyUpdateCallback(streamData->updateId);
    streamData->webRtc->close();
    room->streamMap.erase(localStreamId);
    if(streamData->sessionId.has_value()) {
        _sessionIdToStreamId.erase(streamData->sessionId.value());
    }
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

void StreamApiLowImpl::keyManagement(bool disable) {
    _streamRoomMap.forAll([disable]([[maybe_unused]]const std::string& id, std::shared_ptr<privmx::endpoint::stream::StreamApiLowImpl::StreamRoomData> room) {
        room->streamKeyManager->keyManagement(disable);
    });
}

void StreamApiLowImpl::reconfigureStream(int64_t localStreamId, const std::string& optionsJSON) {
    auto room = getStreamRoomData(localStreamId);
    auto streamData = getStreamData(localStreamId, room);

    std::shared_ptr<WebRTCInterface> webRtc = streamData->webRtc;
    webRtc->updateKeys(room->streamKeyManager->getCurrentWebRtcKeys());
    std::string sdp = webRtc->createOfferAndSetLocalDescription();
    // Publish data on bridge
    auto janusJSEP = utils::TypedObjectFactory::createNewObject<server::JanusJSEP>();
    janusJSEP.sdp(sdp);
    janusJSEP.type("offer");
    auto options = utils::Utils::parseJsonObject(optionsJSON);
    options->set("restart", true);
    options->set("jsep", janusJSEP);
    auto model = utils::TypedObjectFactory::createNewObject<server::StreamReconfigureModel>();
    model.sessionId(streamData->sessionId.value()); //TODO
    model.options(options);
    _serverApi->streamReconfigure(model);
}

void StreamApiLowImpl::subscribeForStreamEvents() {
    if(_streamSubscriptionHelper.hasSubscriptionForModule()) {
        throw AlreadySubscribedException();
    }
    _streamSubscriptionHelper.subscribeForModule();
}

void StreamApiLowImpl::unsubscribeFromStreamEvents() {
    if(!_streamSubscriptionHelper.hasSubscriptionForModule()) {
        throw NotSubscribedException();
    }
    _streamSubscriptionHelper.unsubscribeFromModule();
}

uint32_t StreamApiLowImpl::validateStreamRoomDataIntegrity(server::StreamRoomInfo streamRoom) {
    auto streamRoom_data_entry = streamRoom.data().get(streamRoom.data().size()-1);
    try {
        switch (getStreamRoomEntryDataStructureVersion(streamRoom_data_entry)) {
            case StreamRoomDataSchema::Version::UNKNOWN:
                return UnknownStreamRoomFormatException().getCode();
            case StreamRoomDataSchema::Version::VERSION_5: {
                auto streamRoom_data = utils::TypedObjectFactory::createObjectFromVar<core::dynamic::EncryptedModuleDataV5>(streamRoom_data_entry.data());
                auto dio = _streamRoomDataEncryptorV5.getDIOAndAssertIntegrity(streamRoom_data);
                if(
                    dio.contextId != streamRoom.contextId() ||
                    dio.resourceId != streamRoom.resourceIdOpt("") ||
                    dio.creatorUserId != streamRoom.lastModifier() ||
                    !core::TimestampValidator::validate(dio.timestamp, streamRoom.lastModificationDate())
                ) {
                    return StreamRoomDataIntegrityException().getCode();
                }
                return 0;
            }
        }
    } catch (const core::Exception& e) {
        return e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        return e.getCode();
    } catch (...) {
        return ENDPOINT_CORE_EXCEPTION_CODE;
    } 
    return UnknownStreamRoomFormatException().getCode();
}
