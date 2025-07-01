#ifndef _PRIVMXLIB_ENDPOINT_EVENT_EVENTAPI_IMPL_HPP_
#define _PRIVMXLIB_ENDPOINT_EVENT_EVENTAPI_IMPL_HPP_

#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/privfs/gateway/RpcGateway.hpp>
#include <privmx/endpoint/core/SubscriptionHelper.hpp>
#include <privmx/endpoint/core/encryptors/DataEncryptorV4.hpp>
#include <privmx/endpoint/core/EventChannelManager.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/event/EventKeyProvider.hpp>
#include "privmx/endpoint/event/ServerApi.hpp"
#include "privmx/endpoint/event/EventTypes.hpp"
#include "privmx/endpoint/event/Events.hpp"
#include "privmx/endpoint/event/encryptors/event/EventDataEncryptorV5.hpp"
#include "privmx/endpoint/event/encryptors/event/OldEventDataDecryptor.hpp"

namespace privmx {
namespace endpoint {
namespace event {

class EventApiImpl {
public:
    EventApiImpl(const core::Connection& connection, const privmx::crypto::PrivateKey& userPrivKey, privfs::RpcGateway::Ptr gateway, std::shared_ptr<core::EventMiddleware> eventMiddleware, std::shared_ptr<core::EventChannelManager> eventChannelManager);
    ~EventApiImpl();

    void emitEvent(const std::string& contextId, const std::vector<core::UserWithPubKey>& users, const std::string& channelName, const core::Buffer& eventData);
    void subscribeForCustomEvents(const std::string& contextId, const std::string& channelName);
    void unsubscribeFromCustomEvents(const std::string& contextId, const std::string& channelName);

    void emitEventInternal(const std::string& contextId, InternalContextEventDataV1 event, const std::vector<core::UserWithPubKey>& users);
    bool isInternalContextEvent(const std::string& type, const std::string& channel, Poco::JSON::Object::Ptr eventData, const std::optional<std::string>& internalContextEventType);
    DecryptedInternalContextEventDataV1 extractInternalEventData(const Poco::JSON::Object::Ptr& eventData);
    void subscribeForInternalEvents(const std::string& contextId);
    void unsubscribeFromInternalEvents(const std::string& contextId);
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
    core::SubscriptionHelper _contextSubscriptionHelper;
    core::DataEncryptorV4 _dataEncryptor;
    std::vector<std::string> _forbiddenChannelsNames;
    EventKeyProvider _eventKeyProvider;
    int _notificationListenerId, _connectedListenerId, _disconnectedListenerId;
    EventDataEncryptorV5 _eventDataEncryptorV5;
    OldEventDataDecryptor _oldEventDataDecryptor;
};

}  // namespace event
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_EVENT_EVENTAPI_IMPL_HPP_
