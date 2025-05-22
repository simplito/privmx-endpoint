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
    _subscriptionMap(utils::ThreadSaveMap<std::string, bool>()) {}


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

void SubscriptionHelper::subscribeFor(const std::string& channel, bool silent) {
    _eventChannelManager->subscribeFor(channel);
    if(!silent) {
        _subscriptionMap.set(channel, true);
    }
}

void SubscriptionHelper::unsubscribeFor(const std::string& channel, bool silent) {
    _eventChannelManager->unsubscribeFrom(channel);
    if(!silent) {
        _subscriptionMap.erase(_moduleName);
    }
}

bool SubscriptionHelper::hasSubscriptionForModule() {
    return _subscriptionMap.get(_moduleName).has_value();
}

bool SubscriptionHelper::hasSubscriptionForModuleEntry(const std::string& moduleId) {
    return _subscriptionMap.get(getModuleEntryChannel(moduleId)).has_value();
}

bool SubscriptionHelper::hasSubscriptionForModuleEntryCustomChannel(const std::string& moduleId, const std::string& channelName) {
    return _subscriptionMap.get(getModuleEntryCustomChannel(moduleId, channelName)).has_value();
}

bool SubscriptionHelper::hasSubscriptionForChannel(const std::string& fullChannel) {
    return _subscriptionMap.get(fullChannel).has_value();
}

void SubscriptionHelper::subscribeForModule(bool silent) {
    subscribeFor(_moduleName, silent);
}

void SubscriptionHelper::unsubscribeFromModule(bool silent) {
    unsubscribeFor(_moduleName, silent);
}

void SubscriptionHelper::subscribeForModuleEntry(const std::string& moduleId, bool silent) {
    subscribeFor(getModuleEntryChannel(moduleId), silent);
}

void SubscriptionHelper::unsubscribeFromModuleEntry(const std::string& moduleId, bool silent) {
    unsubscribeFor(getModuleEntryChannel(moduleId), silent);
}

void SubscriptionHelper::subscribeForModuleEntryCustomChannel(const std::string& moduleId, const std::string&  channelName, bool silent) {
    subscribeFor(getModuleEntryCustomChannel(moduleId, channelName), silent);
}

void SubscriptionHelper::unsubscribeFromModuleEntryCustomChannel(const std::string& moduleId, const std::string&  channelName, bool silent) {
    unsubscribeFor(getModuleEntryCustomChannel(moduleId, channelName), silent);
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
    return _map.get(getModuleEntryChannel(moduleId)).has_value();
}

bool SubscriptionHelperExt::hasSubscriptionForModuleEntryCustomChannel(const std::string& moduleId, const std::string&  channelName) {
    return _map.get(getModuleEntryCustomChannel(moduleId, channelName)).has_value();
}

bool SubscriptionHelperExt::hasSubscriptionForChannel(const std::string& fullChannel) {
    return _map.get(fullChannel).has_value();
}

void SubscriptionHelperExt::subscribeForModuleEntry(const std::string& moduleId, const std::string& parentModuleId,  bool silent) {
    _subscriptionHelper.subscribeForModuleEntry(moduleId);
    if(!silent) _map.set(getModuleEntryChannel(moduleId), parentModuleId);
}

void SubscriptionHelperExt::unsubscribeFromModuleEntry(const std::string& moduleId, bool silent) {
    _subscriptionHelper.unsubscribeFromModuleEntry(moduleId);
    if(!silent) _map.erase(getModuleEntryChannel(moduleId));
}

void SubscriptionHelperExt::subscribeForModuleEntryCustomChannel(const std::string& moduleId, const std::string& parentModuleId, const std::string&  channelName,  bool silent) {
    _subscriptionHelper.subscribeForModuleEntryCustomChannel(moduleId, channelName);
    if(!silent) _map.set(getModuleEntryCustomChannel(moduleId, channelName), parentModuleId);
}

void SubscriptionHelperExt::unsubscribeFromModuleEntryCustomChannel(const std::string& moduleId, const std::string&  channelName, bool silent) {
    _subscriptionHelper.unsubscribeFromModuleEntryCustomChannel(moduleId, channelName);
    if(!silent) _map.erase(getModuleEntryCustomChannel(moduleId, channelName));
}

std::string SubscriptionHelperExt::getParentModuleEntryId(const std::string& moduleId) {
    auto tmp = _map.get(getModuleEntryChannel(moduleId));
    return tmp.has_value() ? tmp.value() : std::string();
}