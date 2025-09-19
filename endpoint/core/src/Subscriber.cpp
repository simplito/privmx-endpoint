/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/core/Subscriber.hpp"
#include "privmx/endpoint/core/CoreException.hpp"
#include <privmx/utils/Debug.hpp>
using namespace privmx::endpoint::core;


SubscriptionQueryObj::SubscriptionQueryObj(const std::vector<std::string>& channelPath, const std::vector<SubscriptionQueryObj::QuerySelector>& selectors) : 
    _channelPath(channelPath), _selectors(selectors) {}

SubscriptionQueryObj::SubscriptionQueryObj(const std::string& subscriptionQueryString) {
    auto splittedQuery = privmx::utils::Utils::split(subscriptionQueryString, QUERY_MAIN_SEPARATOR);
    if(splittedQuery.size() > QUERY_MAIN_MAX_SIZE) {
        throw core::InvalidSubscriptionQueryException("query have more then one '|'");
    }
    // extracting query path
    if(splittedQuery.size() > QUERY_PATH_POS) {
        _channelPath = privmx::utils::Utils::split(splittedQuery[QUERY_PATH_POS], QUERY_PATH_SEPARATOR);
    }
    // extracting selectors
    if(splittedQuery.size() > SELECTOR_POS) {
        auto selectors = privmx::utils::Utils::split(splittedQuery[SELECTOR_POS], SELECTORS_SEPARATOR);
        for(const auto& selector: selectors) {
            auto splittedSelector = privmx::utils::Utils::split(selector, SELECTOR_SEPARATOR);
            if(splittedSelector.size() != SELECTOR_SIZE) {
                throw core::InvalidSubscriptionQueryException("selector not in format <key>=<value>");
            }
            _selectors.push_back(
                SubscriptionQueryObj::QuerySelector{
                    .selectorKey = splittedSelector[SELECTOR_TYPE_POS], 
                    .selectorValue = splittedSelector[SELECTOR_ID_POS]
                }
            );
        }
    }
}

std::string SubscriptionQueryObj::toSubscriptionQueryString() const {
    std::string result;
    for(const auto& p: _channelPath) {
        result += p + QUERY_PATH_SEPARATOR;
    }
    result.pop_back();
    result += QUERY_MAIN_SEPARATOR;
    for(const auto& s: _selectors) {
        result += s.selectorKey + SELECTOR_SEPARATOR + s.selectorValue + SELECTORS_SEPARATOR;
    }
    result.pop_back();
    return result;
}


Subscriber::Subscriber(privmx::privfs::RpcGateway::Ptr gateway) : _gateway(gateway) {}

std::vector<std::string> Subscriber::subscribeFor(const std::vector<std::string>& subscriptionQueries) {
    PRIVMX_DEBUG_TIME_START(Subscriber, subscribeFor)
    auto model = utils::TypedObjectFactory::createNewObject<server::SubscribeToChannelsModel>();
    std::vector<SubscriptionQueryObj> parsedSubscriptionQueries;
    for(const auto& subscriptionQueryString : subscriptionQueries) {
        parsedSubscriptionQueries.push_back(SubscriptionQueryObj(subscriptionQueryString));
    }
    assertQuery(parsedSubscriptionQueries);
    auto modelChannels = transform(parsedSubscriptionQueries);
    PRIVMX_DEBUG("Subscriber", "subscribeFor", "channels:" + privmx::utils::Utils::stringifyVar(modelChannels));
    model.channels(modelChannels);
    auto value = privmx::utils::TypedObjectFactory::createObjectFromVar<server::SubscribeToChannelsResult>(
        _gateway->request("subscribeToChannels", model, {.channel_type = rpc::ChannelType::WEBSOCKET})
    );
    PRIVMX_DEBUG_TIME_CHECKPOINT(Subscriber, subscribeFor, dataRecived)
    std::vector<std::string> result;
    {
        std::unique_lock<std::shared_mutex> lock(_map_mutex);
        for(auto channel : modelChannels) {
            bool found = false;
            for(size_t i = 0; i < value.subscriptions().size(); i++) {
                auto subscription = value.subscriptions().get(i);
                if(channel == subscription.channel()) {
                    result.push_back(subscription.subscriptionId());
                    _subscriptionIdToSubscriptionQuery.insert_or_assign(subscription.subscriptionId(), subscription.channel());
                    found = true;
                    value.subscriptions().remove(i);
                    break;
                }
            }
            if(!found) {
                result.push_back("");
            }
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
    {
        std::unique_lock<std::shared_mutex> lock(_map_mutex);
        for(auto subscriptionId: subscriptionIds) {
            _subscriptionIdToSubscriptionQuery.erase(subscriptionId);
        }
    }
    PRIVMX_DEBUG_TIME_STOP(Subscriber, unsubscribeFrom, dataRecived)
}

void Subscriber::unsubscribeFromCurrentlySubscribed() {
    std::vector<std::string> subscriptionIds;
    {
        std::shared_lock<std::shared_mutex> lock(_map_mutex);
        for(auto& s: _subscriptionIdToSubscriptionQuery) {
            subscriptionIds.push_back(s.first);
        }
    }
    if(subscriptionIds.size() > 0) {
        unsubscribeFrom(subscriptionIds);
    }
}

std::optional<std::string> Subscriber::getSubscriptionQuery(const std::string& subscriptionId) {
    std::shared_lock<std::shared_mutex> lock(_map_mutex);
    auto search = Subscriber::_subscriptionIdToSubscriptionQuery.find(subscriptionId);
    if (search == _subscriptionIdToSubscriptionQuery.end()) {
        return std::nullopt;
    }
    return search->second;
}

std::optional<std::string> Subscriber::getSubscriptionQuery(const std::vector<std::string>& subscriptionIds) {
    std::shared_lock<std::shared_mutex> lock(_map_mutex);
    for(auto& subscriptionId : subscriptionIds) {
        auto search = Subscriber::_subscriptionIdToSubscriptionQuery.find(subscriptionId);
        if (search != _subscriptionIdToSubscriptionQuery.end()) {
            return search->second;
        }
    }
    return std::nullopt;
}