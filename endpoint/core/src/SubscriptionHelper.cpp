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
    const std::string& entryName
) : 
    _eventChannelManager(eventChannelManager), 
    _moduleName(moduleName), 
    _entryName(entryName),
    _channelSubscriptionMap(utils::ThreadSaveMap<std::string, std::string>()),
    _subscriptionMap(utils::ThreadSaveMap<std::string, std::string>())
{}

std::string SubscriptionHelper::getModuleChannel(const std::optional<std::string>& eventType) {
    if(eventType.has_value()) {
        return _moduleName + "/" + eventType.value();
    } else {
        return _moduleName;
    }
}
std::string SubscriptionHelper::getModuleCustomChannel(const std::string& channelName) {
    return  getModuleChannel("custom") + "/" + channelName;
}

std::string SubscriptionHelper::getModuleEntryChannel(const std::string& moduleId, const std::optional<std::string>& eventType) {
    if(eventType.has_value()) {
        if(moduleId == "context") {
            return getModuleChannel(_entryName) + "/" + eventType.value() + "|contextId=" + moduleId;
        }
        return getModuleChannel(_entryName) + "/" + eventType.value() + "|containerId=" + moduleId;
    } else {
        if(moduleId == "context") {
            return getModuleChannel(_entryName) + "|contextId=" + moduleId;
        }
        return getModuleChannel(_entryName) + "|containerId=" + moduleId;
    }
}

std::string SubscriptionHelper::getSingleModuleCustomChannel(const std::string& moduleId, const std::string& channelName) {
    if(moduleId == "context") {
        return getModuleCustomChannel(channelName) + "|contextId=" + moduleId;
    }
    return getModuleCustomChannel(channelName) + "|containerId=" + moduleId;
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

bool SubscriptionHelper::hasSubscriptionForModule(const std::vector<std::string>& eventTypes) {
    if(eventTypes.size() == 0) {
        return _channelSubscriptionMap.has(getModuleChannel("create")) &&
            _channelSubscriptionMap.has(getModuleChannel("update")) &&
            _channelSubscriptionMap.has(getModuleChannel("delete")) &&
            _channelSubscriptionMap.has(getModuleChannel("stats"));
    } else {
        bool result = true;
        for(const auto& eventType: eventTypes) {
            result &= _channelSubscriptionMap.has(_moduleName+"/"+eventType);
        }
        return result;
    }
}

bool SubscriptionHelper::hasSubscriptionForModuleEntry(const std::string& moduleId, const std::vector<std::string>& eventTypes) {
    if(eventTypes.size() == 0) {
        return _channelSubscriptionMap.has(getModuleEntryChannel(moduleId));
    } else {
        bool result = true;
        for(const auto& eventType: eventTypes) {
            result &= _channelSubscriptionMap.has(getModuleEntryChannel(moduleId,eventType));
        }
        return result;
    }
}

bool SubscriptionHelper::hasSubscriptionForSingleModuleCustomChannel(const std::string& moduleId, const std::string& channelName) {
    return _channelSubscriptionMap.has(getSingleModuleCustomChannel(moduleId, channelName));
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

void SubscriptionHelper::subscribeForModule(const std::vector<std::string>& eventTypes) {
    if(eventTypes.size() == 0) {
        subscribeFor({getModuleChannel("create"),getModuleChannel("update"),getModuleChannel("delete"),getModuleChannel("stats")});
    } else {
        std::vector<std::string> channels;
        for(const auto& eventType: eventTypes) {
            channels.push_back(getModuleChannel(eventType));
        }
        subscribeFor(channels);
    }
}

void SubscriptionHelper::unsubscribeFromModule(const std::vector<std::string>& eventTypes) {

    if(eventTypes.size() == 0) {
        unsubscribeFor({getModuleChannel("create"),getModuleChannel("update"),getModuleChannel("delete"),getModuleChannel("stats")});
    } else {
        std::vector<std::string> channels;
        for(const auto& eventType: eventTypes) {
            channels.push_back(getModuleChannel(eventType));
        }
        unsubscribeFor(channels);
    }
}

void SubscriptionHelper::subscribeForModuleEntry(const std::string& moduleId, const std::vector<std::string>& eventTypes) {
    if(eventTypes.size() == 0) {
        subscribeFor({getModuleEntryChannel(moduleId)});
    } else {
        std::vector<std::string> channels;
        for(const auto& eventType: eventTypes) {
            channels.push_back(getModuleEntryChannel(moduleId, eventType));
        }
        subscribeFor(channels);
    }
}

void SubscriptionHelper::unsubscribeFromModuleEntry(const std::string& moduleId, const std::vector<std::string>& eventTypes) {

    if(eventTypes.size() == 0) {
        unsubscribeFor({getModuleEntryChannel(moduleId)});
    } else {
        std::vector<std::string> channels;
        for(const auto& eventType: eventTypes) {
            channels.push_back(getModuleEntryChannel(moduleId, eventType));
        }
        unsubscribeFor(channels);
    }
}

void SubscriptionHelper::subscribeForSingleModuleCustomChannel(const std::string& moduleId, const std::string&  channelName) {
    subscribeFor({getSingleModuleCustomChannel(moduleId, channelName)});
}

void SubscriptionHelper::unsubscribeFromSingleModuleCustomChannel(const std::string& moduleId, const std::string&  channelName) {
    unsubscribeFor({getSingleModuleCustomChannel(moduleId, channelName)});
}

void SubscriptionHelper::processSubscriptionNotificationEvent(const std::string& type, const core::NotificationEvent& notification) {
    if (notification.source != core::EventSource::INTERNAL) {
        return;
    }
    if (type == "subscribe") {
        Poco::JSON::Object::Ptr data = notification.data.extract<Poco::JSON::Object::Ptr>();
        std::string channelName = data->has("channel") ? data->getValue<std::string>("channel") : "";
        PRIVMX_DEBUG(
            "SubscriptionHelper", 
            "subscribe" + _moduleName, 
            channelName
        );
    } else if (type == "unsubscribe") {
        Poco::JSON::Object::Ptr data = notification.data.extract<Poco::JSON::Object::Ptr>();
        std::string channelName = data->has("channel") ?  data->getValue<std::string>("channel") : "";
        PRIVMX_DEBUG(
            "SubscriptionHelper", 
            "subscribe" + _moduleName, 
            channelName
        );
    }
}

// ------------------------------------ SubscriptionHelperExt ------------------------------------

SubscriptionHelperExt::SubscriptionHelperExt(std::shared_ptr<EventChannelManager> eventChannelManager, const std::string& moduleName, const std::string& entryName) : 
    _subscriptionHelper(eventChannelManager, moduleName, entryName), _moduleName(moduleName), _entryName(entryName), _map(utils::ThreadSaveMap<std::string, std::string>()) {}


bool SubscriptionHelperExt::hasSubscriptionForModuleEntry(const std::string& moduleId) {
    return _subscriptionHelper.hasSubscriptionForModuleEntry(moduleId);
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
    _map.set(_subscriptionHelper.getModuleEntryChannel(moduleId), parentModuleId);
}

void SubscriptionHelperExt::unsubscribeFromModuleEntry(const std::string& moduleId) {
    _subscriptionHelper.unsubscribeFromModuleEntry(moduleId);
    _map.erase(_subscriptionHelper.getModuleEntryChannel(moduleId));
}

std::string SubscriptionHelperExt::getParentModuleEntryId(const std::string& moduleId) {
    auto tmp = _map.get(_subscriptionHelper.getModuleEntryChannel(moduleId));
    return tmp.has_value() ? tmp.value() : std::string();
}