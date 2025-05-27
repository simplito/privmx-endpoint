/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/core/SubscriptionHelper.hpp"

using namespace privmx::endpoint::core;


SubscriptionHelper::SubscriptionHelper(std::shared_ptr<EventChannelManager> eventChannelManager, const std::string& moduleName, const std::string& entryName) : 
    _eventChannelManager(eventChannelManager), 
    _moduleName(moduleName), 
    _entryName(entryName),
    _channelSubscriptionMap(utils::ThreadSaveMap<std::string, std::string>()),
    _subscriptionMap(utils::ThreadSaveMap<std::string, std::string>()) {}


std::string SubscriptionHelper::getModuleEntryChannel(const std::string& moduleId) {
    if(moduleId == "context") {
        return _moduleName + "/item|contextId=" + moduleId;
    }
    return _moduleName + "/item|containerId=" + moduleId;
}

std::string SubscriptionHelper::getModuleEntryCustomChannel(const std::string& moduleId, const std::string& channelName) {
    if(moduleId == "context") {
        return _moduleName + "/custom/" + channelName + "|contextId=" + moduleId;
    }
    return _moduleName + "/custom/" + channelName + "|containerId=" + moduleId;
}

void SubscriptionHelper::subscribeFor(const std::string& channel) {
    auto subscriptionId = _eventChannelManager->subscribeFor(channel);
    _channelSubscriptionMap.set(channel, subscriptionId);
    _subscriptionMap.set(subscriptionId, channel);
}

void SubscriptionHelper::unsubscribeFor(const std::string& channel) {
    _eventChannelManager->unsubscribeFrom(channel);
    auto subscriptionId = _channelSubscriptionMap.get(channel);
    if(subscriptionId.has_value()) {
        _subscriptionMap.erase(subscriptionId.value());
    }
}

bool SubscriptionHelper::hasSubscriptionForModule() {
    return _channelSubscriptionMap.has(_moduleName);
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
    subscribeFor(_moduleName);
    subscribeFor(_moduleName);
    subscribeFor(_moduleName);
    subscribeFor(_moduleName);
}

void SubscriptionHelper::unsubscribeFromModule() {
    unsubscribeFor(_moduleName);
}

void SubscriptionHelper::subscribeForModuleEntry(const std::string& moduleId) {
    subscribeFor(getModuleEntryChannel(moduleId));
}

void SubscriptionHelper::unsubscribeFromModuleEntry(const std::string& moduleId) {
    unsubscribeFor(getModuleEntryChannel(moduleId));
}

void SubscriptionHelper::subscribeForModuleEntryCustomChannel(const std::string& moduleId, const std::string&  channelName) {
    subscribeFor(getModuleEntryCustomChannel(moduleId, channelName));
}

void SubscriptionHelper::unsubscribeFromModuleEntryCustomChannel(const std::string& moduleId, const std::string&  channelName) {
    unsubscribeFor(getModuleEntryCustomChannel(moduleId, channelName));
}

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