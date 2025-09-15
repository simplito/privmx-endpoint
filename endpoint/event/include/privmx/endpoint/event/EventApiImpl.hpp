#ifndef _PRIVMXLIB_ENDPOINT_EVENT_EVENTAPI_IMPL_HPP_
#define _PRIVMXLIB_ENDPOINT_EVENT_EVENTAPI_IMPL_HPP_

#include <atomic>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/privfs/gateway/RpcGateway.hpp>
#include <privmx/endpoint/core/encryptors/DataEncryptorV4.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/event/EventKeyProvider.hpp>
#include "privmx/endpoint/event/ServerApi.hpp"
#include "privmx/endpoint/event/EventTypes.hpp"
#include "privmx/endpoint/event/Events.hpp"
#include "privmx/endpoint/event/encryptors/event/EventDataEncryptorV5.hpp"
#include "privmx/endpoint/event/encryptors/event/OldEventDataDecryptor.hpp"
#include "privmx/endpoint/event/SubscriberImpl.hpp"

namespace privmx {
namespace endpoint {
namespace event {

class EventApiImpl {
public:
    EventApiImpl(
        const core::Connection& connection, 
        const privmx::crypto::PrivateKey& userPrivKey, 
        privfs::RpcGateway::Ptr gateway, 
        std::shared_ptr<core::EventMiddleware> eventMiddleware
    );
    ~EventApiImpl();

    void emitEvent(const std::string& contextId, const std::vector<core::UserWithPubKey>& users, const std::string& channelName, const core::Buffer& eventData);
    void emitEventInternal(const std::string& contextId, InternalContextEventDataV1 event, const std::vector<core::UserWithPubKey>& users);
    bool isInternalContextEvent(const std::string& type, const std::vector<std::string>& subscriptions, Poco::JSON::Object::Ptr eventData, const std::optional<std::string>& internalContextEventType);
    DecryptedInternalContextEventDataV1 extractInternalEventData(const Poco::JSON::Object::Ptr& eventData);

    std::vector<std::string> subscribeFor(const std::vector<std::string>& subscriptionQueries);
    void unsubscribeFrom(const std::vector<std::string>& subscriptionIds);
    std::string buildSubscriptionQuery(const std::string& channelName, EventSelectorType selectorType, const std::string& selectorId);
    std::string buildSubscriptionQueryInternal(EventSelectorType selectorType, const std::string& selectorId);
private:
    void processNotificationEvent(const std::string& type, const core::NotificationEvent& notification);
    void processConnectedEvent();
    void processDisconnectedEvent();
    void emitEventEx(const std::string& contextId, const std::vector<core::UserWithPubKey>& users, const std::string& channelName, Poco::Dynamic::Var encryptedEventData, const std::string &encryptionKey);
    void validateChannelName(const std::string& channelName);
    bool verifyDecryptedEventDataV5(const DecryptedEventDataV5& data);
    core::Connection _connection;
    privmx::crypto::PrivateKey _userPrivKey;
    ServerApi _serverApi;
    std::shared_ptr<core::EventMiddleware> _eventMiddleware;
    core::DataEncryptorV4 _dataEncryptor;
    std::vector<std::string> _forbiddenChannelsNames;
    EventKeyProvider _eventKeyProvider;
    SubscriberImpl _subscriber;
    int _notificationListenerId, _connectedListenerId, _disconnectedListenerId;
    EventDataEncryptorV5 _eventDataEncryptorV5;
    OldEventDataDecryptor _oldEventDataDecryptor;
};

}  // namespace event
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_EVENT_EVENTAPI_IMPL_HPP_
