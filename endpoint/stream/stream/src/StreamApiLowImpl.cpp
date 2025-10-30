/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/stream/StreamApiLowImpl.hpp"

#include <Poco/URI.h>

#include <chrono>
#include <ctime>
#include <iomanip>
#include <privmx/crypto/EciesEncryptor.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/EndpointUtils.hpp>
#include <privmx/endpoint/core/EventVarSerializer.hpp>
#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/endpoint/core/Factory.hpp>
#include <privmx/endpoint/core/JsonSerializer.hpp>
#include <privmx/endpoint/core/ListQueryMapper.hpp>
#include <privmx/endpoint/core/TimestampValidator.hpp>
#include <privmx/utils/Debug.hpp>

#include "privmx/endpoint/core/UsersKeysResolver.hpp"
#include "privmx/endpoint/stream/DynamicTypes.hpp"
#include "privmx/endpoint/stream/Events.hpp"
#include "privmx/endpoint/stream/StreamException.hpp"
#include "privmx/endpoint/stream/StreamTypes.hpp"
#include "privmx/endpoint/stream/StreamVarDeserializer.hpp"
#include "privmx/utils/TypedObject.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::stream;

int32_t StreamApiLowImpl::nextIdCounter = 0;

StreamApiLowImpl::StreamApiLowImpl(
    const std::shared_ptr<event::EventApiImpl>& eventApi,
    const core::Connection& connection,
    const privfs::RpcGateway::Ptr& gateway,
    const privmx::crypto::PrivateKey& userPrivKey,
    const std::shared_ptr<core::KeyProvider>& keyProvider,
    const std::string& host,
    const std::shared_ptr<core::EventMiddleware>& eventMiddleware
) : ModuleBaseApi(userPrivKey, keyProvider, host, eventMiddleware, connection),
     _eventApi(eventApi),
    _connection(connection.getImpl()),
    _gateway(gateway),
    _userPrivKey(userPrivKey),
    _keyProvider(keyProvider),
    _host(host),
    _eventMiddleware(eventMiddleware),
    _serverApi(std::make_shared<ServerApi>(gateway)),
    _subscriber(stream::SubscriberImpl(gateway))
{
    // streamGetTurnCredentials
    auto model = utils::TypedObjectFactory::createNewObject<server::StreamGetTurnCredentialsModel>();
    auto credentials = _serverApi->streamGetTurnCredentials(model).credentials();
    _notificationListenerId = _eventMiddleware->addNotificationEventListener(std::bind(&StreamApiLowImpl::onNotificationEvent, this, std::placeholders::_1, std::placeholders::_2));
    _connectedListenerId = _eventMiddleware->addConnectedEventListener(std::bind(&StreamApiLowImpl::processConnectedEvent, this));
    _disconnectedListenerId = _eventMiddleware->addDisconnectedEventListener(std::bind(&StreamApiLowImpl::processDisconnectedEvent, this));

    auto internalSubscriptionQuery {_subscriber.getInternalEventsSubscriptionQuery()};
    auto result = _subscriber.subscribeFor({internalSubscriptionQuery});

    _events_consumer_queue = std::make_shared<ThreadSafeQueue<core::NotificationEvent>>();
    _ect_notifier_cancellation_token = privmx::utils::CancellationToken::create();
    _events_consumer_thread = std::thread([&](privmx::utils::CancellationToken::Ptr token) {
        try {
            while (!token->isCancelled()) {
                token->sleep( std::chrono::milliseconds(10));
                if (!_events_consumer_queue->empty()) {
                    processNotificationEvent(_events_consumer_queue->pop());
                }
            }
        } catch (const core::Exception& e) {
            PRIVMX_DEBUG("STREAMS", "STREAM-APA-LOW_IMPL", "_events_consumer_thread core::Exception: " + e.getFull());
            e.rethrow();
        } catch (const privmx::utils::OperationCancelledException& e) {
            PRIVMX_DEBUG("STREAMS", "STREAM-APA-LOW_IMPL", "_events_consumer_thread stop");
        } catch (const std::exception& e) {
            PRIVMX_DEBUG("STREAMS", "STREAM-APA-LOW_IMPL", "_events_consumer_thread std::exception: " + std::string(e.what()));
            throw e;
        }
    }, _ect_notifier_cancellation_token);



    _eventMiddleware->notificationEventListenerAddSubscriptionIds(_notificationListenerId, result);
}

StreamApiLowImpl::~StreamApiLowImpl() {
    if(_ect_notifier_cancellation_token) {
        _ect_notifier_cancellation_token->cancel();
        _events_consumer_thread.join();
    }
    _streamRoomMap.forAll([&]([[maybe_unused]]std::string key,std::shared_ptr<privmx::endpoint::stream::StreamApiLowImpl::StreamRoomData> roomValue) {
        if(roomValue->publisherStream) {
            roomValue->publisherStream.reset();
        }
        if(roomValue->subscriberStream) {
            roomValue->subscriberStream.reset();
        }
        roomValue->webRtc->close(roomValue->streamRoomId);
    });
    _streamRoomMap.clear();
    _eventMiddleware->removeNotificationEventListener(_notificationListenerId);
    _eventMiddleware->removeConnectedEventListener(_connectedListenerId);
    _eventMiddleware->removeDisconnectedEventListener(_disconnectedListenerId);
    _eventApi->unsubscribeFrom(_internalSubscriptionIds);
    PRIVMX_DEBUG("StreamApiLowImpl", "~StreamApiLowImpl", "Done");
}

std::vector<TurnCredentials> StreamApiLowImpl::getTurnCredentials() {
    auto model = utils::TypedObjectFactory::createNewObject<server::StreamGetTurnCredentialsModel>();
    auto credentials = _serverApi->streamGetTurnCredentials(model).credentials();
    std::vector<TurnCredentials> result;
    for(auto credential : credentials) {
        StreamApiLowImpl::assertTurnServerUri(credential.url());
        result.push_back(TurnCredentials{.url=credential.url(), .username=credential.username(), .password=credential.password(), .expirationTime=credential.expirationTime()});
    }
    return result;
}

void StreamApiLowImpl::onNotificationEvent(const std::string& _type, const core::NotificationEvent& _notification) {
    _events_consumer_queue->push(_notification);
}

void StreamApiLowImpl::processNotificationEvent(const core::NotificationEvent& notification) {
        auto type {notification.type};
        PRIVMX_DEBUG("StreamApiLowImpl", "processNotificationEvent", "event type:"+ type);
        Poco::JSON::Object::Ptr data = notification.data.extract<Poco::JSON::Object::Ptr>();

        if(_eventApi->isInternalContextEvent(type, notification.subscriptions, data, "StreamKeyManagementEvent")) {
            PRIVMX_DEBUG("StreamApiLowImpl", "processNotificationEvent", "isInternalContextEvent");
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
        auto subscriptionQuery = _subscriber.getSubscriptionQuery(notification.subscriptions);
        if(!subscriptionQuery.has_value()) {
            return;
        }
        PRIVMX_DEBUG("StreamApiLowImpl", "processNotificationEvent", "Bridge Event: " + type + "\n" + privmx::utils::Utils::stringifyVar(notification.data, true));
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
        } else if (type == "streamPublished" || type == "streamJoined" || type == "streamLeft" ) {
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
            } else if(type == "streamLeft") {
                std::shared_ptr<StreamLeftEvent> event(new StreamLeftEvent());
                event->channel = "stream";
                event->data = eventData;
                _eventMiddleware->emitApiEvent(event);
            }
        }
        else if (type == "streamUnpublished") {
            auto raw = utils::TypedObjectFactory::createObjectFromVar<server::StreamUnpublishedEventData>(data);
            auto eventData = StreamUnpublishedEventData{.streamRoomId=raw.streamRoomId(), .streamId=raw.streamId()};
            std::shared_ptr<StreamUnpublishedEvent> event(new StreamUnpublishedEvent());
            event->channel = "stream";
            event->data = eventData;
            _eventMiddleware->emitApiEvent(event);
        }
        else if (type == "publisherAvailablePublishers") {
            auto raw = utils::TypedObjectFactory::createObjectFromVar<server::CurrentPublishersData>(data);
            auto deserializer = std::make_shared<core::VarDeserializer>();
            auto parsed = deserializer->deserialize<CurrentPublishersData>(Poco::Dynamic::Var(data), "CurrentPublishersData");

            std::shared_ptr<StreamAvailablePublishersEvent> event(new StreamAvailablePublishersEvent());
            event->channel = "stream";
            event->data = parsed;
            _eventMiddleware->emitApiEvent(event);
        }
        else if (type == "streamsUpdated") {
            auto raw = utils::TypedObjectFactory::createObjectFromVar<server::StreamsUpdatedData>(data);

            // update offer via WebRtcInterface
            auto streamRoomId {raw.room()};
            auto roomOpt = _streamRoomMap.get(streamRoomId);
            std::shared_ptr<privmx::endpoint::stream::StreamApiLowImpl::StreamRoomData> room;
            if(!roomOpt.has_value()) {
                throw CannotGetRoomOnStreamsUpdateEventException();
            } else {
                room = roomOpt.value();
            }
            if (!raw.jsepEmpty()) {
                std::string sdp = room->webRtc->createAnswerAndSetDescriptions(room->streamRoomId, raw.jsep().sdp(), raw.jsep().type());
                auto sessionDescription = utils::TypedObjectFactory::createNewObject<server::SessionDescription>();
                SdpWithTypeModel sdpModel = {
                    .sdp = sdp,
                    .type = "answer"
                };

                acceptOfferOnReconfigure(raw.sessionId(), sdpModel);
            }

            // pass event to client
            auto deserializer = std::make_shared<core::VarDeserializer>();
            auto parsed = deserializer->deserialize<StreamsUpdatedData>(Poco::Dynamic::Var(data), "StreamsUpdatedData");
            std::shared_ptr<PublishersStreamsUpdatedEvent> event(new PublishersStreamsUpdatedEvent());
            event->channel = "stream";
            event->data = parsed;
            _eventMiddleware->emitApiEvent(event);
        }
        else {
            std::cerr << "UNRESOLVED EVENT in CPP layer: '" << type << "'"<< std::endl;
        }
}

void StreamApiLowImpl::processConnectedEvent() {

}

void StreamApiLowImpl::processDisconnectedEvent() {

}

std::shared_ptr<privmx::endpoint::stream::StreamApiLowImpl::StreamRoomData> StreamApiLowImpl::createEmptyStreamRoomData(const std::string& streamRoomId, std::shared_ptr<WebRTCInterface> webRtc) {
    auto model = privmx::utils::TypedObjectFactory::createNewObject<server::StreamRoomGetModel>();
    model.id(streamRoomId);
    auto streamRoom = _serverApi->streamRoomGet(model).streamRoom();
    std::shared_ptr<StreamRoomData> streamRoomData = std::make_shared<StreamRoomData>(
        std::make_shared<StreamKeyManager>(_eventApi, _keyProvider, _serverApi, _userPrivKey, streamRoomId, streamRoom.contextId(), _notificationListenerId),
        streamRoomId,
        webRtc
    );
    _streamRoomMap.set(
        streamRoomId,
        streamRoomData
    );
    return streamRoomData;
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

void StreamApiLowImpl::joinStreamRoom(const std::string& streamRoomId, std::shared_ptr<WebRTCInterface> webRtc) {
    createEmptyStreamRoomData(streamRoomId, webRtc);
    // TODO
}
void StreamApiLowImpl::leaveStreamRoom(const std::string& streamRoomId) {
    auto room = getStreamRoomData(streamRoomId);
    if(room->publisherStream) {
        //gently close publisherStream
        if(room->publisherStream->streamHandle.has_value()) {
            _streamHandleToRoomId.erase(room->publisherStream->streamHandle.value());
        }
    }
    if(room->subscriberStream) {
        //gently close subscriberStream
        if(room->subscriberStream->streamHandle.has_value()) {
            _streamHandleToRoomId.erase(room->subscriberStream->streamHandle.value());
        }
    }
    room->streamKeyManager->removeKeyUpdateCallback(room->keyUpdateCallbackId);
    //kill all webRTC pearConnections
    room->webRtc->close(room->streamRoomId);
    //stop StreamKeyManager
    room->streamKeyManager.reset();
    // Final clenup
    _streamRoomMap.erase(streamRoomId);
}

StreamHandle StreamApiLowImpl::createStream(const std::string& streamRoomId) {
    auto streamHandle {nextId()};
    auto room = getStreamRoomData(streamRoomId);
    if(room->publisherStream) {
        throw StreamIsPublished();
    }
    PRIVMX_DEBUG("STREAMS", "API", std::to_string(streamHandle) + ": STREAM Sender")
    _streamHandleToRoomId.set(streamHandle, streamRoomId);
    room->publisherStream = std::make_shared<StreamData>(
        StreamData{
            .sessionId=std::nullopt, 
            .streamHandle=streamHandle
        }
    );
    return streamHandle;
}


// Publishing stream
RemoteStreamId StreamApiLowImpl::publishStream(const StreamHandle& streamHandle) {
    auto room = getStreamRoomData(streamHandle);
    if(!room->publisherStream || room->publisherStream->streamHandle != streamHandle) {
        throw StreamHandleNotInitialized();
    }
    auto streamData = room->publisherStream;
    room->webRtc->updateKeys(room->streamRoomId, room->streamKeyManager->getCurrentWebRtcKeys());
    std::string sdp = room->webRtc->createOfferAndSetLocalDescription(room->streamRoomId);
    // Publish data on bridge
    auto sessionDescription = utils::TypedObjectFactory::createNewObject<server::SessionDescription>();
    sessionDescription.sdp(sdp);
    sessionDescription.type("offer");
    auto model = utils::TypedObjectFactory::createNewObject<server::StreamPublishModel>();
    model.streamRoomId(room->streamRoomId);
    model.offer(sessionDescription);
    auto result = _serverApi->streamPublish(model);
    streamData->sessionId = result.sessionId();
    // update/set sessionId in webrtc (for Janus - trickle)
    room->webRtc->updateSessionId(room->streamRoomId, result.sessionId(), std::string("publisher"));
    // Set remote description
    room->webRtc->setAnswerAndSetRemoteDescription(room->streamRoomId, result.answer().sdp(), result.answer().type());
    return result.sessionId();
}

void StreamApiLowImpl::unpublishStream(const StreamHandle& streamHandle) {
    auto room = getStreamRoomData(streamHandle);
    if(!room->publisherStream) {
        throw StreamHandleNotInitialized();
    }
    auto streamData = room->publisherStream;
    if(streamData->sessionId.has_value()) {
        server::StreamUnpublishModel model = privmx::utils::TypedObjectFactory::createNewObject<server::StreamUnpublishModel>();
        model.sessionId(streamData->sessionId.value());
        _serverApi->streamUnpublish(model);
    }
    room->webRtc->close(room->streamRoomId);
    _streamHandleToRoomId.erase(streamHandle);
    room->publisherStream.reset();
}

void StreamApiLowImpl::subscribeToRemoteStreams(const std::string& streamRoomId, const std::vector<StreamSubscription>& subscriptions, const Settings& options) {
    auto room = getStreamRoomData(streamRoomId);
    // Sending Request to Bridge
    auto model = utils::TypedObjectFactory::createNewObject<server::StreamsSubscribeModel>();
    model.streamRoomId(streamRoomId);

    auto itemsToAdd = utils::TypedObjectFactory::createNewList<server::StreamSubscription>();
    for(size_t i = 0; i < subscriptions.size(); i++) {
        auto item = utils::TypedObjectFactory::createNewObject<server::StreamSubscription>();
        item.streamId(subscriptions[i].streamId);
        if (subscriptions[i].streamTrackId) {
            item.streamTrackId(subscriptions[i].streamTrackId.value());
        }
        itemsToAdd.add(item);
    }
    model.subscriptionsToAdd(itemsToAdd);
    auto subscribeResult = _serverApi->streamsSubscribeToRemote(model);

    // update/set sessionId in webrtc (for Janus - trickle)
    room->webRtc->updateSessionId(streamRoomId, subscribeResult.sessionId(), std::string("subscriber"));

    room->subscriberStream = std::make_shared<StreamData>(
        StreamData{
            .sessionId = subscribeResult.sessionId(),
            .streamHandle = StreamHandle()
        }
    );

    // !!! peerConnection re-negotiation is optional as not always we will get an offer from MediaServer when calling in joinStream()
    if (!subscribeResult.offerEmpty()) {
        std::string sdp = room->webRtc->createAnswerAndSetDescriptions(streamRoomId, subscribeResult.offer().sdp(), subscribeResult.offer().type());

        SdpWithTypeModel sdpModel = {
            .sdp = sdp,
            .type = "answer"
        };
        acceptOfferOnReconfigure(subscribeResult.sessionId(), sdpModel);
    }
    
    std::set<RemoteStreamId> streamIds;
    for(const auto& subscription : subscriptions) {
        streamIds.insert(subscription.streamId);
    }
    sendStreamKeyRequest(room, streamIds);
}


void StreamApiLowImpl::modifyRemoteStreamsSubscriptions(const std::string& streamRoomId, const std::vector<StreamSubscription>& subscriptionsToAdd, const std::vector<StreamSubscription>& subscriptionsToRemove, const Settings& options) {
    auto room = getStreamRoomData(streamRoomId);
    // Sending Request to Bridge
    auto model = utils::TypedObjectFactory::createNewObject<server::StreamsModifySubscriptionsModel>();
    model.streamRoomId(streamRoomId);

    // subscriptions to add
    auto itemsToAdd = utils::TypedObjectFactory::createNewList<server::StreamSubscription>();
    for(size_t i = 0; i < subscriptionsToAdd.size(); i++) {
        auto item = utils::TypedObjectFactory::createNewObject<server::StreamSubscription>();
        item.streamId(subscriptionsToAdd[i].streamId);
        if (subscriptionsToAdd[i].streamTrackId) {
            item.streamTrackId(subscriptionsToAdd[i].streamTrackId.value());
        }
        itemsToAdd.add(item);
    }
    model.subscriptionsToAdd(itemsToAdd);

    // subscriptions to remove
    auto itemsToRemove = utils::TypedObjectFactory::createNewList<server::StreamSubscription>();
    for(size_t i = 0; i < subscriptionsToRemove.size(); i++) {
        auto item = utils::TypedObjectFactory::createNewObject<server::StreamSubscription>();
        item.streamId(subscriptionsToRemove[i].streamId);
        if (subscriptionsToRemove[i].streamTrackId) {
            item.streamTrackId(subscriptionsToRemove[i].streamTrackId.value());
        }
        itemsToRemove.add(item);
    }
    model.subscriptionsToRemove(itemsToRemove);

    auto result = _serverApi->streamsModifyRemoteSubscriptions(model);

    // update/set sessionId in webrtc (for Janus - trickle)
    room->webRtc->updateSessionId(streamRoomId, result.sessionId(), std::string("subscriber"));

    room->subscriberStream = std::make_shared<StreamData>(
        StreamData{
            .sessionId = result.sessionId(),
            .streamHandle = StreamHandle()
        }
    );

    // !!! peerConnection re-negotiation is optional as not always we will get an offer from MediaServer when calling in joinStream()
    if (!result.offerEmpty()) {
        std::string sdp = room->webRtc->createAnswerAndSetDescriptions(streamRoomId, result.offer().sdp(), result.offer().type());

        SdpWithTypeModel sdpModel = {
            .sdp = sdp,
            .type = "answer"
        };
        acceptOfferOnReconfigure(result.sessionId(), sdpModel);
    }

    std::set<RemoteStreamId> streamIds;
    for(const auto& subscription : subscriptionsToAdd) {
        streamIds.insert(subscription.streamId);
    }
    sendStreamKeyRequest(room, streamIds);
}

void StreamApiLowImpl::unsubscribeFromRemoteStreams(const std::string& streamRoomId, const std::vector<StreamSubscription>& subscriptionsToRemove) {
    auto model = privmx::utils::TypedObjectFactory::createNewObject<server::StreamsUnsubscribeModel>();
    model.streamRoomId(streamRoomId);

    auto itemsToRemove = utils::TypedObjectFactory::createNewList<server::StreamSubscription>();
    for(size_t i = 0; i < subscriptionsToRemove.size(); i++) {
        auto item = utils::TypedObjectFactory::createNewObject<server::StreamSubscription>();
        item.streamId(subscriptionsToRemove[i].streamId);
        if (subscriptionsToRemove[i].streamTrackId) {
            item.streamTrackId(subscriptionsToRemove[i].streamTrackId.value());
        }
        itemsToRemove.add(item);
    }

    model.subscriptionsToRemove(itemsToRemove);
    _serverApi->streamsUnsubscribeFromRemote(model);
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

std::shared_ptr<StreamApiLowImpl::StreamRoomData> StreamApiLowImpl::getStreamRoomData(const std::string& streamRoomId) {
    auto room = _streamRoomMap.get(streamRoomId);
    if(!room.has_value()) {
        throw StreamRoomConnectionNotInitialized();
    }
    return room.value();
}

std::shared_ptr<StreamApiLowImpl::StreamRoomData> StreamApiLowImpl::getStreamRoomData(const StreamHandle& streamHandle) {
    auto streamRoomId = _streamHandleToRoomId.get(streamHandle);
    if(!streamRoomId.has_value()) {
        throw IncorrectStreamHandleException();
    }
    return getStreamRoomData(streamRoomId.value());
}

void StreamApiLowImpl::keyManagement(const std::string& streamRoomId, bool disable) {
    auto streamRoom = _streamRoomMap.get(streamRoomId);
    if(streamRoom.has_value()) {
        streamRoom.value()->streamKeyManager->keyManagement(disable);
    }
}
std::vector<std::string> StreamApiLowImpl::subscribeFor(const std::vector<std::string>& subscriptionQueries) {
    auto result = _subscriber.subscribeFor(subscriptionQueries);
    _eventMiddleware->notificationEventListenerAddSubscriptionIds(_notificationListenerId, result);
    return result;
}

void StreamApiLowImpl::unsubscribeFrom(const std::vector<std::string>& subscriptionIds) {
    _subscriber.unsubscribeFrom(subscriptionIds);
    _eventMiddleware->notificationEventListenerRemoveSubscriptionIds(_notificationListenerId, subscriptionIds);
}

std::string StreamApiLowImpl::buildSubscriptionQuery(EventType eventType, EventSelectorType selectorType, const std::string& selectorId) {
    return SubscriberImpl::buildQuery(eventType, selectorType, selectorId);
}

std::pair<core::ModuleKeys, int64_t> StreamApiLowImpl::getModuleKeysAndVersionFromServer(std::string moduleId) {
    auto params = privmx::utils::TypedObjectFactory::createNewObject<stream::server::StreamRoomGetModel>();
    params.id(moduleId);
    auto stream = _serverApi->streamRoomGet(params).streamRoom();
    // validate stream Data before returning data
    assertStreamRoomDataIntegrity(stream);
    return std::make_pair(streamRoomToModuleKeys(stream), stream.version());
}

core::ModuleKeys StreamApiLowImpl::streamRoomToModuleKeys(server::StreamRoomInfo stream) {
    return core::ModuleKeys{
        .keys=stream.keys(),
        .currentKeyId=stream.keyId(),
        .moduleSchemaVersion=getStreamRoomEntryDataStructureVersion(stream.data().get(stream.data().size()-1)),
        .moduleResourceId=stream.resourceIdOpt(""),
        .contextId = stream.contextId()
    };
}

void StreamApiLowImpl::assertStreamRoomDataIntegrity(server::StreamRoomInfo streamRoom) {
    auto streamRoom_data_entry = streamRoom.data().get(streamRoom.data().size()-1);
        switch (getStreamRoomEntryDataStructureVersion(streamRoom_data_entry)) {
            case StreamRoomDataSchema::Version::UNKNOWN:
                throw UnknowStreamRoomFormatException();
            case StreamRoomDataSchema::Version::VERSION_5: {
                auto streamRoom_data = utils::TypedObjectFactory::createObjectFromVar<core::dynamic::EncryptedModuleDataV5>(streamRoom_data_entry.data());
                auto dio = _streamRoomDataEncryptorV5.getDIOAndAssertIntegrity(streamRoom_data);
                if(
                    dio.contextId != streamRoom.contextId() ||
                    dio.resourceId != streamRoom.resourceIdOpt("") ||
                    dio.creatorUserId != streamRoom.lastModifier() ||
                    !core::TimestampValidator::validate(dio.timestamp, streamRoom.lastModificationDate())
                ) {
                    throw StreamRoomDataIntegrityException();
                }
                return;
            }
        }
    throw UnknowStreamRoomFormatException();
}

uint32_t StreamApiLowImpl::validateStreamRoomDataIntegrity(server::StreamRoomInfo streamRoom) {
    try {
        assertStreamRoomDataIntegrity(streamRoom);
    } catch (const core::Exception& e) {
        return e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        return e.getCode();
    } catch (...) {
        return ENDPOINT_CORE_EXCEPTION_CODE;
    } 
    return UnknownStreamRoomFormatException().getCode();
}

void StreamApiLowImpl::assertTurnServerUri(const std::string& uri) {
    try {
        Poco::URI tmp(uri);
        if(tmp.getScheme() != "turn") {
            throw InvalidTurnServerURIException();
        }
    }catch (Poco::SyntaxException &e){
        throw InvalidTurnServerURIException();
    }
}
void StreamApiLowImpl::trickle(const int64_t sessionId, const std::string& candidateAsJson) {
    auto model = utils::TypedObjectFactory::createNewObject<server::StreamTrickleModel>();
    model.sessionId(sessionId);
    model.candidate(utils::TypedObjectFactory::createObjectFromVar<dynamic::RTCIceCandidate>(privmx::utils::Utils::parseJson(candidateAsJson)));
    _serverApi->trickle(model);
}

void StreamApiLowImpl::acceptOfferOnReconfigure(const int64_t sessionId, const SdpWithTypeModel& sdp) {
    auto sessionDescription = utils::TypedObjectFactory::createNewObject<server::SessionDescription>();
    sessionDescription.sdp(sdp.sdp);
    sessionDescription.type("answer");
    auto model = utils::TypedObjectFactory::createNewObject<server::StreamAcceptOfferModel>();
    model.sessionId(sessionId);
    model.answer(sessionDescription);
    _serverApi->streamAcceptOffer(model);
}

void StreamApiLowImpl::sendStreamKeyRequest(std::shared_ptr<privmx::endpoint::stream::StreamApiLowImpl::StreamRoomData> room, const std::set<RemoteStreamId>& streamIds) {
    // get Room for contextId
    auto modelGetRoom = privmx::utils::TypedObjectFactory::createNewObject<server::StreamRoomGetModel>();
    modelGetRoom.id(room->streamRoomId);
    auto streamRoom = _serverApi->streamRoomGet(modelGetRoom).streamRoom();

    // get Streams for userId
    auto modelStreams = privmx::utils::TypedObjectFactory::createNewObject<server::StreamListModel>();
    modelStreams.streamRoomId(room->streamRoomId);
    auto streamsList = _serverApi->streamList(modelStreams).list();

    // get users for pubKey
    Poco::JSON::Object::Ptr query = new Poco::JSON::Object;
    Poco::JSON::Object::Ptr queryId = new Poco::JSON::Object;
    Poco::JSON::Array::Ptr usersIds = new Poco::JSON::Array;

    for(auto s: streamsList) {
        if ( std::find(streamIds.begin(), streamIds.end(), s.streamId()) != streamIds.end() ) {
            usersIds->add(s.userId());
        }
    }
    PRIVMX_DEBUG("STREAMS", "joinStream", "listContextUsers users:  " + privmx::utils::Utils::stringify(usersIds))
    queryId->set("$in", usersIds);
    query->set("#userId", queryId);

    core::PagingList<core::UserInfo> userInfoList = _connection->listContextUsers(
        streamRoom.contextId(), 
        core::PagingQuery{
            .skip = 0,
            .limit = usersIds->size(),
            .sortOrder = "desc",
            .lastId = std::nullopt,
            .sortBy = std::nullopt,
            .queryAsJson = privmx::utils::Utils::stringify(query)
        }
    ); 

    
    std::vector<core::UserWithPubKey> toSend;
    for(auto userInfo: userInfoList.readItems) {
        PRIVMX_DEBUG("STREAMS", "joinStream", "Request Send: " + userInfo.user.userId)
        toSend.push_back(userInfo.user);
    }
    room->streamKeyManager->requestKey(toSend);
}