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
#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/EciesEncryptor.hpp>
#include <privmx/utils/Debug.hpp>

#include "privmx/endpoint/event/EventApiImpl.hpp"
#include "privmx/endpoint/event/EventException.hpp"
#include "privmx/endpoint/event/Events.hpp"
#include "privmx/endpoint/event/Constants.hpp"
#include "privmx/endpoint/core/EventBuilder.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::event;

EventApiImpl::EventApiImpl(const core::Connection& connection, const privmx::crypto::PrivateKey& userPrivKey, privfs::RpcGateway::Ptr gateway, std::shared_ptr<core::EventMiddleware> eventMiddleware) :
    _connection(connection),
    _userPrivKey(userPrivKey),
    _serverApi(ServerApi(gateway)),
    _eventMiddleware(eventMiddleware),
    _forbiddenChannelsNames({INTERNAL_EVENT_CHANNEL_NAME}), 
    _eventKeyProvider(EventKeyProvider(userPrivKey)),
    _subscriber(SubscriberImpl(gateway))
{
    _notificationListenerId = _eventMiddleware->addNotificationEventListener(std::bind(&EventApiImpl::processNotificationEvent, this, std::placeholders::_1, std::placeholders::_2));
    _connectedListenerId = _eventMiddleware->addConnectedEventListener(std::bind(&EventApiImpl::processConnectedEvent, this));
    _disconnectedListenerId = _eventMiddleware->addDisconnectedEventListener(std::bind(&EventApiImpl::processDisconnectedEvent, this));
}

EventApiImpl::~EventApiImpl() {
    _eventMiddleware->removeNotificationEventListener(_notificationListenerId);
    _eventMiddleware->removeConnectedEventListener(_connectedListenerId);
    _eventMiddleware->removeDisconnectedEventListener(_disconnectedListenerId);
    _subscriber.unsubscribeFromCurrentlySubscribed();
}

void EventApiImpl::emitEvent(const std::string& contextId, const std::vector<core::UserWithPubKey>& users, const std::string& channelName, const core::Buffer& eventData) {
    validateChannelName(channelName);
    auto key = _eventKeyProvider.generateKey();
    auto toEncrypt = ContextEventDataToEncryptV5{
        ContextEventDataV5{
            .data = eventData,
            .type = std::nullopt,
            .dio = _connection.getImpl()->createDIO(contextId, "")
        }
    };
    emitEventEx(contextId, users, channelName, _eventDataEncryptorV5.encrypt(toEncrypt, _userPrivKey, key), key);
}

void EventApiImpl::emitEventInternal(const std::string& contextId, InternalContextEventDataV1 event, const std::vector<core::UserWithPubKey>& users) {
    auto key = _eventKeyProvider.generateKey();
    auto toEncrypt = ContextEventDataToEncryptV5{
        ContextEventDataV5{
            .data = event.data,
            .type = event.type,
            .dio = _connection.getImpl()->createDIO(contextId, "")
        }
    };
    emitEventEx(contextId, users, INTERNAL_EVENT_CHANNEL_NAME, _eventDataEncryptorV5.encrypt(toEncrypt, _userPrivKey, key), key);
}

bool EventApiImpl::isInternalContextEvent(const std::string& type, const std::vector<std::string>& subscriptions, Poco::JSON::Object::Ptr eventData, const std::optional<std::string>& internalContextEventType) {
    //check if type == "custom" and channel == "context/<contextId>/internal"
    PRIVMX_DEBUG("EventApiImpl", "isInternalContextEvent", "eventType: " + type)
    if(type == "custom") {
        auto channel = _subscriber.getSubscriptionQuery(subscriptions);
        if(!channel.has_value()) return false;
        PRIVMX_DEBUG("EventApiImpl", "isInternalContextEvent", "eventChannel: " + channel.value())
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::ContextCustomEventData>(eventData);
        if( !raw.idEmpty() && channel.value() == "context/custom/" INTERNAL_EVENT_CHANNEL_NAME "|contextId=" + raw.id() && raw.eventData().type() == typeid(Poco::JSON::Object::Ptr)) {
            auto rawEventDataJSON = raw.eventData().extract<Poco::JSON::Object::Ptr>();
            if(rawEventDataJSON->has("type")) {
                if(!internalContextEventType.has_value()) {
                    return true;
                } else {
                    if(rawEventDataJSON->getValue<std::string>("type") == internalContextEventType.value()) {
                        return true;
                    }
                }
            }
        }
    }
    return false;
}

DecryptedInternalContextEventDataV1 EventApiImpl::extractInternalEventData(const Poco::JSON::Object::Ptr& eventData) {
    auto rawEvent = utils::TypedObjectFactory::createObjectFromVar<server::ContextCustomEventData>(eventData);
    DecryptedInternalContextEventDataV1 result;
    result.dataStructureVersion = EventDataSchema::Version::VERSION_5;
    auto decryptedKey = _eventKeyProvider.decryptKey(rawEvent.key(), crypto::PublicKey::fromBase58DER(rawEvent.author().pub()));
    result.statusCode = decryptedKey.statusCode;
    if(result.statusCode == 0) {
        auto tmp = _eventDataEncryptorV5.decrypt(
            utils::TypedObjectFactory::createObjectFromVar<server::EncryptedContextEventDataV5>(rawEvent.eventData()),
            crypto::PublicKey::fromBase58DER(rawEvent.author().pub()),
            decryptedKey.key
        );
        result.statusCode = tmp.statusCode;
        result.data = tmp.data;
        result.type = tmp.type.has_value() ? tmp.type.value() : "";
        if(result.statusCode == 0) {
            result.statusCode = verifyDecryptedEventDataV5(tmp) ? 0 : core::ExceptionConverter::getCodeOfUserVerificationFailureException();
        }
    }
    return result;
}

void EventApiImpl::processNotificationEvent(const std::string& type, const core::NotificationEvent& notification) {
    Poco::JSON::Object::Ptr data = notification.data.extract<Poco::JSON::Object::Ptr>();
    if(type != "custom") return;
    std::optional<std::string> subscriptionQuery = _subscriber.getSubscriptionQuery(notification.subscriptions);
    if(subscriptionQuery.has_value()) {
        std::string channel = subscriptionQuery.value();
        auto rawEvent = utils::TypedObjectFactory::createObjectFromVar<server::ContextCustomEventData>(data);
        // fix if not internal check
        if(channel == "context/custom/" INTERNAL_EVENT_CHANNEL_NAME "|contextId=" + rawEvent.id()) return;
        auto resultEventData = ContextCustomEventData{
            .contextId = rawEvent.id(), 
            .userId = rawEvent.author().id(), 
            .payload = core::Buffer(),
            .statusCode = 0,
            .schemaVersion = EventDataSchema::Version::UNKNOWN
        };
        if (rawEvent.eventData().type() == typeid(Poco::JSON::Object::Ptr)) {
            auto decryptedKey = _eventKeyProvider.decryptKey(rawEvent.key(), crypto::PublicKey::fromBase58DER(rawEvent.author().pub()));
            resultEventData.statusCode = decryptedKey.statusCode;
            resultEventData.schemaVersion = EventDataSchema::Version::VERSION_5;
            if(decryptedKey.statusCode == 0) {
                auto tmp = _eventDataEncryptorV5.decrypt(
                    utils::TypedObjectFactory::createObjectFromVar<server::EncryptedContextEventDataV5>(rawEvent.eventData()),
                    crypto::PublicKey::fromBase58DER(rawEvent.author().pub()),
                    decryptedKey.key
                );
                resultEventData.payload = tmp.data;
                resultEventData.statusCode = tmp.statusCode;
                if(resultEventData.statusCode == 0) {
                    resultEventData.statusCode = verifyDecryptedEventDataV5(tmp) ? 0 : core::ExceptionConverter::getCodeOfUserVerificationFailureException();
                }
            }
        } else if (rawEvent.eventData().isString()) {
            resultEventData.schemaVersion = EventDataSchema::Version::VERSION_1;
            auto tmp = _oldEventDataDecryptor.decryptV1(
                rawEvent.eventData().convert<std::string>(), 
                crypto::PublicKey::fromBase58DER(rawEvent.author().pub()),
                rawEvent.key(),
                _userPrivKey
            );
            resultEventData.payload = tmp.data;
            resultEventData.statusCode = tmp.statusCode;
        }
        auto customChannelName = privmx::utils::Utils::split(privmx::utils::Utils::split(channel, "/")[2], "|")[0];
        auto event = core::EventBuilder::buildEvent<privmx::endpoint::event::ContextCustomEvent>("context/" + rawEvent.id() + "/" + customChannelName, resultEventData, notification);
        _eventMiddleware->emitApiEvent(event);
    }
}

void EventApiImpl::processConnectedEvent() {
}

void EventApiImpl::processDisconnectedEvent() {
}

void EventApiImpl::emitEventEx(const std::string& contextId, const std::vector<core::UserWithPubKey>& users, const std::string& channelName, Poco::Dynamic::Var encryptedEventData, const std::string &encryptionKey) {
    server::ContextEmitCustomEventModel model = privmx::utils::TypedObjectFactory::createNewObject<server::ContextEmitCustomEventModel>();
    model.contextId(contextId);
    model.data(encryptedEventData);
    model.channel(channelName);
    model.users(_eventKeyProvider.prepareKeysList(users, encryptionKey));
    _serverApi.contextSendCustomEvent(model);
    PRIVMX_DEBUG("EventApiImpl", "emitEventEx", privmx::utils::Utils::stringify(model, true));
}

void EventApiImpl::validateChannelName(const std::string& channelName) {
    if(std::find(_forbiddenChannelsNames.begin(), _forbiddenChannelsNames.end(), channelName) != _forbiddenChannelsNames.end()) {
        throw ForbiddenChannelNameException();
    }
}

bool EventApiImpl::verifyDecryptedEventDataV5(const DecryptedEventDataV5& data) {
    std::vector<core::VerificationRequest> verifierInput {};
    verifierInput.push_back(core::VerificationRequest{
        .contextId = data.dio.contextId,
        .senderId = data.dio.creatorUserId,
        .senderPubKey = data.dio.creatorPubKey,
        .date = data.dio.timestamp,
        .bridgeIdentity = data.dio.bridgeIdentity
    });
    std::vector<bool> verified;
    verified =_connection.getImpl()->getUserVerifier()->verify(verifierInput);
    return verified[0];
}

std::vector<std::string> EventApiImpl::subscribeFor(const std::vector<std::string>& subscriptionQueries) {
    auto result = _subscriber.subscribeFor(subscriptionQueries);
    _eventMiddleware->notificationEventListenerAddSubscriptionIds(_notificationListenerId, result);
    return result;
}

std::vector<std::string> EventApiImpl::subscribeForInternal(const std::vector<std::string>& subscriptionQueries, int notificationListenerId) {
    auto result = _subscriber.subscribeFor(subscriptionQueries);
    _eventMiddleware->notificationEventListenerAddSubscriptionIds(notificationListenerId, result);
    return result;
}

void EventApiImpl::unsubscribeFrom(const std::vector<std::string>& subscriptionIds) {
    _subscriber.unsubscribeFrom(subscriptionIds);
    _eventMiddleware->notificationEventListenerRemoveSubscriptionIds(_notificationListenerId, subscriptionIds);
}

void EventApiImpl::unsubscribeFromInternal(const std::vector<std::string>& subscriptionIds, int notificationListenerId) {
    _subscriber.unsubscribeFrom(subscriptionIds);
    _eventMiddleware->notificationEventListenerRemoveSubscriptionIds(notificationListenerId, subscriptionIds);
}

std::string EventApiImpl::buildSubscriptionQuery(const std::string& channelName, EventSelectorType selectorType, const std::string& selectorId) {
    return SubscriberImpl::buildQuery(channelName, selectorType, selectorId);
}

std::string EventApiImpl::buildSubscriptionQueryInternal(EventSelectorType selectorType, const std::string& selectorId) {
    return SubscriberImpl::buildQuery(INTERNAL_EVENT_CHANNEL_NAME, selectorType, selectorId, true);
}