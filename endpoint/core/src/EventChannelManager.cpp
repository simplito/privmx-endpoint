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

std::vector<Subscription> EventChannelManager::subscribeFor(const std::vector<std::string>& channels) {
    std::vector<Subscription> result;
    std::vector<std::string> toSubscribe;
    for(size_t i = 0; i < channels.size(); ++i) {
        auto channel = channels[i];
        auto subscription = _map.get(channel);
        if(subscription.has_value() && subscription.value().count > 0) {
            PRIVMX_DEBUG("EventChannelManager", "subscribeFor", "subscribed on channel: " + channel + " " + std::to_string(subscription.value().count))
            subscription.value().count++;
            _map.set(channel, subscription.value());
            result.push_back(Subscription{.subscriptionId=subscription.value().subscriptionId, .channel=channel});
        } else {
            PRIVMX_DEBUG("EventChannelManager", "subscribeFor", "subscribing to channel: " + channel)
            toSubscribe.push_back(channel);
        }
    }
    if(toSubscribe.size() > 0) {
        PRIVMX_DEBUG("EventChannelManager", "subscribeFor", "sending request to serwer")
        auto model = utils::TypedObjectFactory::createNewObject<server::SubscribeToChannelsModel>();
        auto modleChannels = utils::TypedObjectFactory::createNewList<std::string>();
        for(auto channel: toSubscribe) {
            modleChannels.add(channel);
        }
        model.channels(modleChannels);
        auto value = privmx::utils::TypedObjectFactory::createObjectFromVar<server::SubscribeToChannelsResult>(
            _gateway->request("subscribeToChannels", model, {.channel_type = rpc::ChannelType::WEBSOCKET})
        );
        for(auto subscription: value.subscriptions()) {
            _map.set(subscription.channel(), SubscriptionCount{.count = 1, .subscriptionId = subscription.subscriptionId()});
            // send internal event 
            Poco::JSON::Object::Ptr data = new Poco::JSON::Object();
            data->set("channel", subscription.channel()); 
            _eventMiddleware->emitNotificationEvent("subscribe", NotificationEvent{
                .source = EventSource::INTERNAL,
                .type = "subscribe",
                .data = data,
                .version = 0,
                .timestamp = 0,
                .subscriptions = {}
            });
            result.push_back(Subscription{.subscriptionId=subscription.subscriptionId(), .channel=subscription.channel()});
        }
    }
    return result;
}

void EventChannelManager::unsubscribeFrom(const std::vector<std::string>& channels) {
    std::vector<std::string> toUnsubscribe;
    std::vector<std::string> unsubscribeChannels;
    for(size_t i = 0; i < channels.size(); ++i) {
        auto channel = channels[i];
        auto subscription = _map.get(channel);
        if(subscription.has_value() && subscription.value().count > 1) {
            PRIVMX_DEBUG("EventChannelManager", "unsubscribeFrom", "unsubscribed on channel: " + channel + " " + std::to_string(subscription.value().count))
            subscription.value().count--;
            _map.set(channel, subscription.value());
        } else if (subscription.value().count == 1) {
            PRIVMX_DEBUG("EventChannelManager", "unsubscribeFrom", "unsubscribed to channel: " + channel)
            toUnsubscribe.push_back(subscription.value().subscriptionId);
            unsubscribeChannels.push_back(channel);
        } else {
            _map.erase(channel);
        }
    }

    if(unsubscribeChannels.size() > 0) {
        PRIVMX_DEBUG("EventChannelManager", "unsubscribeFrom", "sending request to serwer")
        auto model = utils::TypedObjectFactory::createNewObject<server::UnsubscribeFromChannelsModel>();
        auto subscriptionsIds = utils::TypedObjectFactory::createNewList<std::string>();
        for(auto subscriptionId: toUnsubscribe) {
            subscriptionsIds.add(subscriptionId);
        }
        model.subscriptionsIds(subscriptionsIds);
        _gateway->request("unsubscribeFromChannels", model, {.channel_type = rpc::ChannelType::WEBSOCKET});
        for(auto channel: unsubscribeChannels) {
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
        }
    }
}