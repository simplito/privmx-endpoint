/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/core/EventChannelManager.hpp"
#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/core/ServerTypes.hpp"
#include "privmx/utils/Debug.hpp"

using namespace privmx::endpoint::core;

EventChannelManager::EventChannelManager(privfs::RpcGateway::Ptr gateway, std::shared_ptr<EventMiddleware> eventMiddleware) : 
    _gateway(gateway), _eventMiddleware(eventMiddleware) {}

std::string EventChannelManager::subscribeFor(std::string channel) {
    auto subscription = _map.get(channel);
    if(subscription.has_value() && subscription.value().count > 0) {
        PRIVMX_DEBUG("EventChannelManager", "subscribeFor", "subscribed on channel: " + subscription.value().count)
        subscription.value().count++;
        _map.set(channel, subscription.value());
        return subscription.value().subscriptionId;
    } else {
        PRIVMX_DEBUG("EventChannelManager", "subscribeFor", "subscribing to channel")
        auto model = utils::TypedObjectFactory::createNewObject<server::SubscribeToChannelModel>();
        model.channel(channel);
        auto value = privmx::utils::TypedObjectFactory::createObjectFromVar<server::SubscribeToChannelResult>(
            _gateway->request("subscribeToChannel", model, {.channel_type = rpc::ChannelType::WEBSOCKET})
        );
        _map.set(channel, Subscription{.count = 1, .subscriptionId = value.subscriptionId()});
        // send internal event 
        Poco::JSON::Object::Ptr data = new Poco::JSON::Object();
        data->set("channel", channel); 
        _eventMiddleware->emitNotificationEvent("subscribe", NotificationEvent{
            .source = EventSource::INTERNAL,
            .type = "subscribe",
            .data = data,
            .version = 0,
            .timestamp = 0,
            .subscriptions = {}
        });
        return value.subscriptionId();
    }
}

void EventChannelManager::unsubscribeFrom(std::string channel) {
    auto subscription = _map.get(channel);
    if(subscription.has_value()) {
        if(subscription.value().count > 1) {
            PRIVMX_DEBUG("EventChannelManager", "subscribeFor", "unsubscribed on channel: " + subscription.value().count)
            subscription.value().count--;
            _map.set(channel, subscription.value());
        } else if (subscription.value().count == 1) {
            PRIVMX_DEBUG("EventChannelManager", "subscribeFor", "unsubscribing to channel")
            auto model = utils::TypedObjectFactory::createNewObject<server::UnsubscribeFromChannelsModel>();
            auto subscriptionsIds = utils::TypedObjectFactory::createNewList<std::string>();
            subscriptionsIds.add(subscription.value().subscriptionId);
            model.subscriptionsIds(subscriptionsIds);
            _gateway->request("unsubscribeFromChannels", model, {.channel_type = rpc::ChannelType::WEBSOCKET});
            _map.erase(channel);
            // send internal event 
            Poco::JSON::Object::Ptr data = new Poco::JSON::Object();
            data->set("channel", channel); 
            _eventMiddleware->emitNotificationEvent("unsubscribe", NotificationEvent{
                .source = EventSource::INTERNAL,
                .type = "unsubscribe",
                .data = data,
                .version = 0,
                .timestamp = 0,
                .subscriptions = {}
            });
        } else {
            _map.erase(channel);
        }
    }
}