/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/core/Subscriber.hpp"
#include <privmx/utils/Debug.hpp>
using namespace privmx::endpoint::core;

Subscriber::Subscriber(privmx::privfs::RpcGateway::Ptr gateway) : _gateway(gateway) {}

std::vector<std::string> Subscriber::subscribeFor(const std::vector<std::string>& subscriptionQueries) {
    PRIVMX_DEBUG_TIME_START(Subscriber, subscribeFor)
    auto model = utils::TypedObjectFactory::createNewObject<server::SubscribeToChannelsModel>();
    auto modleChannels = utils::TypedObjectFactory::createNewList<std::string>();
    for(auto subscriptionQuery: subscriptionQueries) {
        assertQuery(subscriptionQuery);
        modleChannels.add(transform(subscriptionQuery));
    }
    PRIVMX_DEBUG("Subscriber", "subscribeFor", "channels:" + privmx::utils::Utils::stringifyVar(modleChannels));
    model.channels(modleChannels);
    auto value = privmx::utils::TypedObjectFactory::createObjectFromVar<server::SubscribeToChannelsResult>(
        _gateway->request("subscribeToChannels", model, {.channel_type = rpc::ChannelType::WEBSOCKET})
    );
    PRIVMX_DEBUG_TIME_CHECKPOINT(Subscriber, subscribeFor, dataRecived)
    std::vector<std::string> result;
    for(auto channel: modleChannels) {
        bool found = false;
        for(auto subscription : value.subscriptions()) {
            if(channel == subscription.channel()) {
                result.push_back(subscription.subscriptionId());
                found = true;
            }
        }
        if(!found) {
            result.push_back("");
        }
    }
    PRIVMX_DEBUG_TIME_STOP(Subscriber, subscribeFor)
    return result;
}

void Subscriber::unsubscribeFrom(const std::vector<std::string>& subscriptionIds) {
    PRIVMX_DEBUG_TIME_START(Subscriber, unsubscribeFrom)
    auto model = utils::TypedObjectFactory::createNewObject<server::UnsubscribeFromChannelsModel>();
    auto subscriptionsIds = utils::TypedObjectFactory::createNewList<std::string>();
    for(auto subscriptionId: subscriptionIds) {
        subscriptionsIds.add(subscriptionId);
    }
    PRIVMX_DEBUG("Subscriber", "unsubscribeFrom", "subscriptionsIds:" + privmx::utils::Utils::stringifyVar(subscriptionsIds));
    model.subscriptionsIds(subscriptionsIds);
    _gateway->request("unsubscribeFromChannels", model, {.channel_type = rpc::ChannelType::WEBSOCKET});
    PRIVMX_DEBUG_TIME_STOP(Subscriber, unsubscribeFrom, dataRecived)
}

