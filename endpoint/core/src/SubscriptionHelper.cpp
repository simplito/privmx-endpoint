/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/core/SubscriptionHelper.hpp"
#include <privmx/utils/Debug.hpp>

using namespace privmx::endpoint::core;


SubscriptionHelper::SubscriptionHelper(
    std::shared_ptr<EventChannelManager> eventChannelManager, 
    const std::string& moduleName, 
    const std::string& entryName,
    std::function<void()> onModuleSubscription,
    std::function<void()> onModuleUnsubscription
) : 
    _eventChannelManager(eventChannelManager), 
    _moduleName(moduleName), 
    _entryName(entryName),
    _moduleCreateSubscription(false),
    _moduleUpdateSubscription(false),
    _moduleDeleteSubscription(false),
    _moduleStatsSubscription(false),
    _onModuleSubscription(onModuleSubscription),
    _onModuleUnsubscription(onModuleUnsubscription),
    _channelSubscriptionMap(utils::ThreadSaveMap<std::string, std::string>()),
    _subscriptionMap(utils::ThreadSaveMap<std::string, std::string>())
{}


std::string SubscriptionHelper::getModuleEntryChannel(const std::string& moduleId) {
    if(moduleId == "context") {
        return _moduleName + "/" + _entryName + "|contextId=" + moduleId;
    }
    return _moduleName + "/" + _entryName + "|containerId=" + moduleId;
}

std::string SubscriptionHelper::getModuleEntryCustomChannel(const std::string& moduleId, const std::string& channelName) {
    if(moduleId == "context") {
        return _moduleName + "/custom/" + channelName + "|contextId=" + moduleId;
    }
    return _moduleName + "/custom/" + channelName + "|containerId=" + moduleId;
}

void SubscriptionHelper::subscribeFor(const std::vector<std::string>& channels) {
    auto subscriptions = _eventChannelManager->subscribeFor(channels);
    for(auto subscription: subscriptions) {
        _channelSubscriptionMap.set(subscription.channel, subscription.subscriptionId);
        _subscriptionMap.set(subscription.subscriptionId, subscription.channel);
    }
}

void SubscriptionHelper::unsubscribeFor(const std::vector<std::string>& channels) {
    _eventChannelManager->unsubscribeFrom(channels);
    for(auto channel: channels) {
        auto subscriptionId = _channelSubscriptionMap.get(channel);
        if(subscriptionId.has_value()) {
            _subscriptionMap.erase(subscriptionId.value());
        }
    }
}

bool SubscriptionHelper::hasSubscriptionForModule() {
    return _channelSubscriptionMap.has(_moduleName+"/create") &&
           _channelSubscriptionMap.has(_moduleName+"/update") &&
           _channelSubscriptionMap.has(_moduleName+"/delete") &&
           _channelSubscriptionMap.has(_moduleName+"/stats");
}

bool SubscriptionHelper::hasSubscriptionForModuleEntry(const std::string& moduleId) {
    return _channelSubscriptionMap.has(getModuleEntryChannel(moduleId));
}

bool SubscriptionHelper::hasSubscriptionForModuleEntryCustomChannel(const std::string& moduleId, const std::string& channelName) {
    return _channelSubscriptionMap.has(getModuleEntryCustomChannel(moduleId, channelName));
}

bool SubscriptionHelper::hasSubscriptionForChannel(const std::string& fullChannel) {
    return _channelSubscriptionMap.has(fullChannel);
}

bool SubscriptionHelper::hasSubscription(const std::vector<std::string>& subscriptionIds) {
    for(auto subscriptionId : subscriptionIds) {
        if(_subscriptionMap.has(subscriptionId)) {
            return true;
        }
    }
    return false;
}

std::string SubscriptionHelper::getChannel(const std::vector<std::string>& subscriptionIds) {
    for(auto subscriptionId : subscriptionIds) {
        auto tmp = _subscriptionMap.get(subscriptionId);
        if(tmp.has_value()) {
            return tmp.value();
        }
    }
    return "";
}

void SubscriptionHelper::subscribeForModule() {
    subscribeFor({_moduleName+"/create",_moduleName+"/update",_moduleName+"/delete",_moduleName+"/stats"});
}

void SubscriptionHelper::unsubscribeFromModule() {
    unsubscribeFor({_moduleName+"/create",_moduleName+"/update",_moduleName+"/delete",_moduleName+"/stats"});
}

void SubscriptionHelper::subscribeForModuleEntry(const std::string& moduleId) {
    subscribeFor({getModuleEntryChannel(moduleId)});
}

void SubscriptionHelper::unsubscribeFromModuleEntry(const std::string& moduleId) {
    unsubscribeFor({getModuleEntryChannel(moduleId)});
}

void SubscriptionHelper::subscribeForModuleEntryCustomChannel(const std::string& moduleId, const std::string&  channelName) {
    subscribeFor({getModuleEntryCustomChannel(moduleId, channelName)});
}

void SubscriptionHelper::unsubscribeFromModuleEntryCustomChannel(const std::string& moduleId, const std::string&  channelName) {
    unsubscribeFor({getModuleEntryCustomChannel(moduleId, channelName)});
}


void SubscriptionHelper::processSubscriptionNotificationEvent(const std::string& type, const core::NotificationEvent& notification) {
    if (notification.source != core::EventSource::INTERNAL) {
        return;
    }
    if (type == "subscribe") {
        Poco::JSON::Object::Ptr data = notification.data.extract<Poco::JSON::Object::Ptr>();
        std::string channelName = data->has("channel") ? data->getValue<std::string>("channel") : "";
        if(channelName        == _moduleName+"/create") {
            _moduleCreateSubscription = true;
        } else if(channelName == _moduleName+"/update") {
            _moduleUpdateSubscription = true;
        } else if(channelName == _moduleName+"/delete") {
            _moduleDeleteSubscription = true;
        } else if(channelName == _moduleName+"/stats") {
            _moduleStatsSubscription  = true;
        }
        if(_moduleCreateSubscription && _moduleUpdateSubscription && _moduleDeleteSubscription && _moduleStatsSubscription) {
            _onModuleSubscription();
        }
        PRIVMX_DEBUG(
            "SubscriptionHelper", 
            "CacheStatus:" + _moduleName, 
            std::to_string(_moduleCreateSubscription) + 
            std::to_string(_moduleUpdateSubscription) + 
            std::to_string(_moduleDeleteSubscription) + 
            std::to_string(_moduleStatsSubscription)
        )
    } else if (type == "unsubscribe") {
        Poco::JSON::Object::Ptr data = notification.data.extract<Poco::JSON::Object::Ptr>();
        std::string channelName = data->has("channel") ?  data->getValue<std::string>("channel") : "";
        if (channelName == _moduleName+"/create") {
            _moduleCreateSubscription = false;
            _onModuleUnsubscription();
        } else if (channelName == _moduleName+"/update") {
            _moduleUpdateSubscription = false;
            _onModuleUnsubscription();
        } else if (channelName == _moduleName+"/delete") {
            _moduleDeleteSubscription = false;
            _onModuleUnsubscription();
        } else if (channelName == _moduleName+"/stats") {
            _moduleStatsSubscription  = false;
            _onModuleUnsubscription();
        }
        PRIVMX_DEBUG(
            "SubscriptionHelper", 
            "CacheStatus:" + _moduleName, 
            std::to_string(_moduleCreateSubscription) + 
            std::to_string(_moduleUpdateSubscription) + 
            std::to_string(_moduleDeleteSubscription) + 
            std::to_string(_moduleStatsSubscription)
        )
    }
}

// ------------------------------------ SubscriptionHelperExt ------------------------------------

SubscriptionHelperExt::SubscriptionHelperExt(std::shared_ptr<EventChannelManager> eventChannelManager, const std::string& moduleName, const std::string& entryName) : 
    _subscriptionHelper(eventChannelManager, moduleName, entryName), _moduleName(moduleName), _entryName(entryName), _map(utils::ThreadSaveMap<std::string, std::string>()) {}

std::string SubscriptionHelperExt::getModuleEntryChannel(const std::string& moduleId) {
    return _moduleName + "/" + moduleId + "/" + _entryName;
}

std::string SubscriptionHelperExt::getModuleEntryCustomChannel(const std::string& moduleId, const std::string& channelName) {
    return _moduleName + "/" + moduleId + "/" + channelName;
}

bool SubscriptionHelperExt::hasSubscriptionForModuleEntry(const std::string& moduleId) {
    return _subscriptionHelper.hasSubscriptionForModuleEntry(moduleId);
}

bool SubscriptionHelperExt::hasSubscriptionForModuleEntryCustomChannel(const std::string& moduleId, const std::string&  channelName) {
    return _subscriptionHelper.hasSubscriptionForModuleEntryCustomChannel(moduleId, channelName);
}

bool SubscriptionHelperExt::hasSubscriptionForChannel(const std::string& fullChannel) {
    return _subscriptionHelper.hasSubscriptionForChannel(fullChannel);
}

bool SubscriptionHelperExt::hasSubscription(const std::vector<std::string>& subscriptionIds) {
    return _subscriptionHelper.hasSubscription(subscriptionIds);
}

std::string SubscriptionHelperExt::getChannel(const std::vector<std::string>& subscriptionIds) {
    return _subscriptionHelper.getChannel(subscriptionIds);
}

void SubscriptionHelperExt::subscribeForModuleEntry(const std::string& moduleId, const std::string& parentModuleId) {
    _subscriptionHelper.subscribeForModuleEntry(moduleId);
    _map.set(getModuleEntryChannel(moduleId), parentModuleId);
}

void SubscriptionHelperExt::unsubscribeFromModuleEntry(const std::string& moduleId) {
    _subscriptionHelper.unsubscribeFromModuleEntry(moduleId);
    _map.erase(getModuleEntryChannel(moduleId));
}

void SubscriptionHelperExt::subscribeForModuleEntryCustomChannel(const std::string& moduleId, const std::string& parentModuleId, const std::string&  channelName) {
    _subscriptionHelper.subscribeForModuleEntryCustomChannel(moduleId, channelName);
    _map.set(getModuleEntryCustomChannel(moduleId, channelName), parentModuleId);
}

void SubscriptionHelperExt::unsubscribeFromModuleEntryCustomChannel(const std::string& moduleId, const std::string&  channelName) {
    _subscriptionHelper.unsubscribeFromModuleEntryCustomChannel(moduleId, channelName);
    _map.erase(getModuleEntryCustomChannel(moduleId, channelName));
}

std::string SubscriptionHelperExt::getParentModuleEntryId(const std::string& moduleId) {
    auto tmp = _map.get(getModuleEntryChannel(moduleId));
    return tmp.has_value() ? tmp.value() : std::string();
}