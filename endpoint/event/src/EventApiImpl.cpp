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

#include "privmx/endpoint/event/EventApiImpl.hpp"
#include "privmx/endpoint/event/EventException.hpp"
#include "privmx/endpoint/event/Events.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::event;

EventApiImpl::EventApiImpl(const privmx::crypto::PrivateKey& userPrivKey, privfs::RpcGateway::Ptr gateway, std::shared_ptr<core::EventMiddleware> eventMiddleware, std::shared_ptr<core::EventChannelManager> eventChannelManager) :
    _userPrivKey(userPrivKey),
    _serverApi(ServerApi(gateway)),
    _eventMiddleware(eventMiddleware),
    _contextSubscriptionHelper(core::SubscriptionHelper(eventChannelManager, "context", "contexts")),
    _forbiddenChannelsNames({INTERNAL_EVENT_CHANNEL_NAME}) 
{
    _notificationListenerId = _eventMiddleware->addNotificationEventListener(std::bind(&EventApiImpl::processNotificationEvent, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
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
    if(_contextSubscriptionHelper.hasSubscriptionForElementCustom(contextId, channelName)) {
        throw AlreadySubscribedException();
    }
    _contextSubscriptionHelper.subscribeForElementCustom(contextId, channelName);
}
void EventApiImpl::unsubscribeFromCustomEvents(const std::string& contextId, const std::string& channelName) {
    validateChannelName(channelName);
    if(!_contextSubscriptionHelper.hasSubscriptionForElementCustom(contextId, channelName)) {
        throw NotSubscribedException();
    }
    _contextSubscriptionHelper.unsubscribeFromElementCustom(contextId, channelName);
}

void EventApiImpl::emitEventInternal(const std::string& contextId, InternalContextEvent event, const std::vector<core::UserWithPubKey>& users) {
    auto key = privmx::crypto::Crypto::randomBytes(32);
    server::EncryptedInternalContextEvent encryptedEvent = privmx::utils::TypedObjectFactory::createNewObject<server::EncryptedInternalContextEvent>();
    encryptedEvent.type(event.type);
    encryptedEvent.encryptedData(_dataEncryptor.signAndEncryptAndEncode( event.data, _userPrivKey, key));
    emitEventEx(contextId, users, INTERNAL_EVENT_CHANNEL_NAME, encryptedEvent, key);
}

bool EventApiImpl::isInternalContextEvent(const std::string& type, const std::string& channel, Poco::JSON::Object::Ptr eventData, const std::optional<std::string>& internalContextEventType) {
    //check if type == "custom" and channel == "context/<contextId>/internal"
    if(type == "custom") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::ContextCustomEventData>(eventData);
        if( !raw.idEmpty() && channel == "context/" + raw.id() + "/" INTERNAL_EVENT_CHANNEL_NAME && raw.eventData().type() == typeid(Poco::JSON::Object::Ptr)) {
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
    auto raw = utils::TypedObjectFactory::createObjectFromVar<server::ContextCustomEventData>(eventData);
    auto rawEventData = utils::TypedObjectFactory::createObjectFromVar<server::EncryptedInternalContextEvent>(raw.eventData());
    auto encKey = privmx::crypto::EciesEncryptor::decryptFromBase64(_userPrivKey, raw.key(), crypto::PublicKey::fromBase58DER(raw.author().pub()));
    auto decryptedData =  _dataEncryptor.decodeAndDecryptAndVerify(rawEventData.encryptedData(), _userPrivKey.getPublicKey(), encKey);
    return InternalContextEvent{.type=rawEventData.type(), .data=decryptedData};
}

void EventApiImpl::subscribeForInternalEvents(const std::string& contextId) {
    _contextSubscriptionHelper.subscribeForElementCustom(contextId, INTERNAL_EVENT_CHANNEL_NAME);
}

void EventApiImpl::unsubscribeFromInternalEvents(const std::string& contextId) {
    _contextSubscriptionHelper.unsubscribeFromElementCustom(contextId, INTERNAL_EVENT_CHANNEL_NAME);
}

void EventApiImpl::processNotificationEvent(const std::string& type, const std::string& channel, const Poco::JSON::Object::Ptr& data) {
    if(type == "custom" && _contextSubscriptionHelper.hasSubscriptionForChannel(channel) && data->get("eventData").isString()) {
        auto rawEvent = utils::TypedObjectFactory::createObjectFromVar<server::ContextCustomEventData>(data);
        if(channel == "context/" + rawEvent.id() + "/" INTERNAL_EVENT_CHANNEL_NAME) return;
        auto encKey = privmx::crypto::EciesEncryptor::decryptFromBase64(
            _userPrivKey, 
            rawEvent.key()
        );
        auto decryptedData = _dataEncryptor.decodeAndDecryptAndVerify(
            rawEvent.eventData().convert<std::string>(), 
            crypto::PublicKey::fromBase58DER(rawEvent.author().pub()), 
            encKey
        );
        std::shared_ptr<privmx::endpoint::event::ContextCustomEvent> event(new privmx::endpoint::event::ContextCustomEvent());
        event->channel = channel;
        event->data = ContextCustomEventData{
            .contextId = rawEvent.id(), 
            .userId = rawEvent.author().id(), 
            .payload = decryptedData
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