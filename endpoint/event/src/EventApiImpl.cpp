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
#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/EciesEncryptor.hpp>
#include <privmx/utils/Debug.hpp>

#include "privmx/endpoint/event/EventApiImpl.hpp"
#include "privmx/endpoint/event/EventException.hpp"
#include "privmx/endpoint/event/Events.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::event;

EventApiImpl::EventApiImpl(const privmx::crypto::PrivateKey& userPrivKey, privfs::RpcGateway::Ptr gateway, std::shared_ptr<core::EventMiddleware> eventMiddleware, std::shared_ptr<core::EventChannelManager> eventChannelManager) :
    _userPrivKey(userPrivKey),
    _serverApi(ServerApi(gateway)),
    _eventMiddleware(eventMiddleware),
    _contextSubscriptionHelper(core::SubscriptionHelper(eventChannelManager, "context")),
    _forbiddenChannelsNames({INTERNAL_EVENT_CHANNEL_NAME}) 
{
    _notificationListenerId = _eventMiddleware->addNotificationEventListener(std::bind(&EventApiImpl::processNotificationEvent, this, std::placeholders::_1, std::placeholders::_2));
    _connectedListenerId = _eventMiddleware->addConnectedEventListener(std::bind(&EventApiImpl::processConnectedEvent, this));
    _disconnectedListenerId = _eventMiddleware->addDisconnectedEventListener(std::bind(&EventApiImpl::processDisconnectedEvent, this));
}

EventApiImpl::~EventApiImpl() {
    _eventMiddleware->removeNotificationEventListener(_notificationListenerId);
    _eventMiddleware->removeConnectedEventListener(_connectedListenerId);
    _eventMiddleware->removeDisconnectedEventListener(_disconnectedListenerId);
}

void EventApiImpl::emitEvent(const std::string& contextId, const std::vector<core::UserWithPubKey>& users, const std::string& channelName, const core::Buffer& eventData) {
    validateChannelName(channelName);
    auto key = privmx::crypto::Crypto::randomBytes(32);
    emitEventEx(contextId, users, channelName, _dataEncryptor.signAndEncryptAndEncode( eventData, _userPrivKey, key), key);
}

void EventApiImpl::subscribeForCustomEvents(const std::string& contextId, const std::string& channelName) {
    validateChannelName(channelName);
    if(_contextSubscriptionHelper.hasSubscriptionForModuleEntryCustomChannel(contextId, channelName)) {
        throw AlreadySubscribedException();
    }
    _contextSubscriptionHelper.subscribeForModuleEntryCustomChannel(contextId, channelName);
}
void EventApiImpl::unsubscribeFromCustomEvents(const std::string& contextId, const std::string& channelName) {
    validateChannelName(channelName);
    if(!_contextSubscriptionHelper.hasSubscriptionForModuleEntryCustomChannel(contextId, channelName)) {
        throw NotSubscribedException();
    }
    _contextSubscriptionHelper.unsubscribeFromModuleEntryCustomChannel(contextId, channelName);
}

void EventApiImpl::emitEventInternal(const std::string& contextId, InternalContextEvent event, const std::vector<core::UserWithPubKey>& users) {
    auto key = privmx::crypto::Crypto::randomBytes(32);
    server::EncryptedInternalContextEvent encryptedEvent = privmx::utils::TypedObjectFactory::createNewObject<server::EncryptedInternalContextEvent>();
    encryptedEvent.type(event.type);
    encryptedEvent.encryptedData(_dataEncryptor.signAndEncryptAndEncode( event.data, _userPrivKey, key));
    emitEventEx(contextId, users, INTERNAL_EVENT_CHANNEL_NAME, encryptedEvent, key);
}

bool EventApiImpl::isInternalContextEvent(const std::string& type, const std::vector<std::string>& subscriptions, Poco::JSON::Object::Ptr eventData, const std::optional<std::string>& internalContextEventType) {
    //check if type == "custom" and channel == "context/<contextId>/internal"
    if(type == "custom") {
        std::string channel = _contextSubscriptionHelper.getChannel(subscriptions);
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::ContextCustomEventData>(eventData);
        if( !raw.idEmpty() && channel == "context/custom/" INTERNAL_EVENT_CHANNEL_NAME "|contextId=" + raw.id() && raw.eventData().type() == typeid(Poco::JSON::Object::Ptr)) {
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

InternalContextEvent EventApiImpl::extractInternalEventData(const Poco::JSON::Object::Ptr& eventData) {
    //it should be used after successful isInternalContextEvent
    auto raw = utils::TypedObjectFactory::createObjectFromVar<server::ContextCustomEventData>(eventData);
    auto rawEventData = utils::TypedObjectFactory::createObjectFromVar<server::EncryptedInternalContextEvent>(raw.eventData());
    core::Buffer decryptedData;
    int64_t statusCode = 0;
    try {
        auto encKey = privmx::crypto::EciesEncryptor::decryptFromBase64(
            _userPrivKey, 
            raw.key(), 
            crypto::PublicKey::fromBase58DER(raw.author().pub())
        );
        decryptedData = _dataEncryptor.decodeAndDecryptAndVerify(
            rawEventData.encryptedData(), 
            crypto::PublicKey::fromBase58DER(raw.author().pub()), 
            encKey
        );
    } catch (const privmx::endpoint::core::Exception& e) {
        statusCode = e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        statusCode = core::ExceptionConverter::convert(e).getCode();
    } catch (...) {
        statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
    }
    return InternalContextEvent{.type=rawEventData.type(), .data=decryptedData, .statusCode=statusCode};
}

void EventApiImpl::subscribeForInternalEvents(const std::string& contextId) {
    _contextSubscriptionHelper.subscribeForModuleEntryCustomChannel(contextId, INTERNAL_EVENT_CHANNEL_NAME);
}

void EventApiImpl::unsubscribeFromInternalEvents(const std::string& contextId) {
    _contextSubscriptionHelper.unsubscribeFromModuleEntryCustomChannel(contextId, INTERNAL_EVENT_CHANNEL_NAME);
}

void EventApiImpl::processNotificationEvent(const std::string& type, const core::NotificationEvent& notification) {
    Poco::JSON::Object::Ptr data = notification.data.extract<Poco::JSON::Object::Ptr>();
    if(type == "custom" && _contextSubscriptionHelper.hasSubscription(notification.subscriptions) && data->get("eventData").isString()) {
        std::string channel = _contextSubscriptionHelper.getChannel(notification.subscriptions);
        auto rawEvent = utils::TypedObjectFactory::createObjectFromVar<server::ContextCustomEventData>(data);
        // fix if not internal check
        if(channel == "context/custom/" INTERNAL_EVENT_CHANNEL_NAME "|contextId=" + rawEvent.id()) return;
        core::Buffer decryptedData;
        std::string customChannelName = "";
        int64_t statusCode = 0;
        try {
            auto encKey = privmx::crypto::EciesEncryptor::decryptFromBase64(
                _userPrivKey, 
                rawEvent.key()
            );
            decryptedData = _dataEncryptor.decodeAndDecryptAndVerify(
                rawEvent.eventData().convert<std::string>(), 
                crypto::PublicKey::fromBase58DER(rawEvent.author().pub()),
                encKey
            );
            customChannelName = privmx::utils::Utils::split(privmx::utils::Utils::split(channel, "/")[2], "|")[0];
        } catch (const privmx::endpoint::core::Exception& e) {
            statusCode = e.getCode();
        } catch (const privmx::utils::PrivmxException& e) {
            statusCode = core::ExceptionConverter::convert(e).getCode();
        } catch (...) {
            statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
        }
        std::shared_ptr<privmx::endpoint::event::ContextCustomEvent> event(new privmx::endpoint::event::ContextCustomEvent());
        event->channel = "context/" + rawEvent.id() + "/" + customChannelName;
        event->data = ContextCustomEventData{
            .contextId = rawEvent.id(), 
            .userId = rawEvent.author().id(), 
            .payload = decryptedData,
            .statusCode = statusCode
        };
        _eventMiddleware->emitApiEvent(event);
    }
}

void EventApiImpl::processConnectedEvent() {
}

void EventApiImpl::processDisconnectedEvent() {
}

void EventApiImpl::emitEventEx(const std::string& contextId, const std::vector<core::UserWithPubKey>& users, const std::string& channelName, Poco::Dynamic::Var encryptedEventData, const std::string &encryptionKey) {
    utils::List<server::UserKey> userKeys = utils::TypedObjectFactory::createNewList<server::UserKey>();
    for (auto user : users) {
        server::UserKey userKey = utils::TypedObjectFactory::createNewObject<server::UserKey>();
        userKey.id(user.userId);
        userKey.key(privmx::crypto::EciesEncryptor::encryptToBase64(crypto::PublicKey::fromBase58DER(user.pubKey), encryptionKey, _userPrivKey));
        userKeys.add(userKey);
    }
    server::ContextEmitCustomEventModel model = privmx::utils::TypedObjectFactory::createNewObject<server::ContextEmitCustomEventModel>();
    model.contextId(contextId);
    model.data(encryptedEventData);
    model.channel(channelName);
    model.users(userKeys);
    _serverApi.contextSendCustomEvent(model);
}

void EventApiImpl::validateChannelName(const std::string& channelName) {
    if(std::find(_forbiddenChannelsNames.begin(), _forbiddenChannelsNames.end(), channelName) != _forbiddenChannelsNames.end()) {
        throw ForbiddenChannelNameException();
    }
}