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
#include "privmx/utils/Debug.hpp"

using namespace privmx::endpoint::core;

EventChannelManager::EventChannelManager(privfs::RpcGateway::Ptr gateway, std::shared_ptr<EventMiddleware> eventMiddleware) : 
    _gateway(gateway), _eventMiddleware(eventMiddleware) {}

void EventChannelManager::subscribeFor(std::string channel) {
    PRIVMX_DEBUG("EventChannelManager", "subscribeFor", channel)
    auto count = _map.get(channel);
    if(count.has_value() && count.value() > 0) {
        PRIVMX_DEBUG("EventChannelManager", "subscribeFor", "subscribed on channel: " + count.value())
        _map.set(channel, count.value()+1);
    } else {
        PRIVMX_DEBUG("EventChannelManager", "subscribeFor", "subscribing to channel")
        Poco::JSON::Object::Ptr model = new Poco::JSON::Object();
        model->set("channel", channel);
        _gateway->request("subscribeToChannel", model, {.channel_type = rpc::ChannelType::WEBSOCKET});
        _eventMiddleware->emitNotificationEvent("subscribe", INTERNAL_EVENT_CHANNEL_NAME, model);
        _map.set(channel, 1);
    }
}

void EventChannelManager::unsubscribeFrom(std::string channel) {
    PRIVMX_DEBUG("EventChannelManager", "unsubscribeFrom", channel)
    auto count = _map.get(channel);
    if(count.has_value()) {
        if(count.value() > 1) {
            PRIVMX_DEBUG("EventChannelManager", "subscribeFor", "unsubscribed on channel: " + count.value())
            _map.set(channel, count.value()-1);
        } else if (count.value() == 1) {
            PRIVMX_DEBUG("EventChannelManager", "subscribeFor", "unsubscribing to channel")
            Poco::JSON::Object::Ptr model = new Poco::JSON::Object();
            model->set("channel", channel);
            _gateway->request("unsubscribeFromChannel", model, {.channel_type = rpc::ChannelType::WEBSOCKET});
            _eventMiddleware->emitNotificationEvent("unsubscribe", INTERNAL_EVENT_CHANNEL_NAME, model);
            _map.erase(channel);
        } else {
            _map.erase(channel);
        }
    }
}