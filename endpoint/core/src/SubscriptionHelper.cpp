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


SubscriptionHelper::SubscriptionHelper(std::shared_ptr<EventChannelManager> eventChannelManager, const std::string& moduleName, const std::string& elementName) : 
    _eventChannelManager(eventChannelManager), 
    _moduleName(moduleName), 
    _elementName(elementName),
    _moduleFlag(false), 
    _subscriptionMap(utils::ThreadSaveMap<std::string, bool>()) {}

bool SubscriptionHelper::hasSubscriptionForModule() {
    return _moduleFlag;
}

bool SubscriptionHelper::hasSubscriptionForElement(const std::string& elementId) {
    return _subscriptionMap.get(_moduleName + "/" + elementId + "/" + _elementName).has_value();
}

bool SubscriptionHelper::hasSubscriptionForElementCustom(const std::string& elementId, const std::string&  channelName) {
    return _subscriptionMap.get(_moduleName + "/" + elementId + "/" + channelName).has_value();
}

bool SubscriptionHelper::hasSubscriptionForChannel(const std::string& fullChannel) {
    if(fullChannel == _moduleName && _moduleFlag) return true;
    return _subscriptionMap.get(fullChannel).has_value();
}

void SubscriptionHelper::subscribeForModule(bool silent) {
    _eventChannelManager->subscribeFor(_moduleName);
    if(!silent) {
        _moduleFlag = true;
        _subscriptionMap.set(_moduleName, true);
    }
}

void SubscriptionHelper::unsubscribeFromModule(bool silent) {
    _eventChannelManager->unsubscribeFrom(_moduleName);
    if(!silent) {
        _moduleFlag = false;
        _subscriptionMap.erase(_moduleName);
    }
}

void SubscriptionHelper::subscribeForElement(const std::string& elementId, bool silent) {
    _eventChannelManager->subscribeFor(_moduleName + "/" + elementId + "/" + _elementName);
    if(!silent) _subscriptionMap.set(_moduleName + "/" + elementId + "/" + _elementName, true);
}

void SubscriptionHelper::unsubscribeFromElement(const std::string& elementId, bool silent) {
    _eventChannelManager->unsubscribeFrom(_moduleName + "/" + elementId + "/" + _elementName);
    if(!silent) _subscriptionMap.erase(_moduleName + "/" + elementId + "/" + _elementName);
}

void SubscriptionHelper::subscribeForElementCustom(const std::string& elementId, const std::string&  channelName, bool silent) {
    _eventChannelManager->subscribeFor(_moduleName + "/" + elementId + "/" + channelName);
    if(!silent) _subscriptionMap.set(_moduleName + "/" + elementId + "/" + channelName, true);
}

void SubscriptionHelper::unsubscribeFromElementCustom(const std::string& elementId, const std::string&  channelName, bool silent) {
    _eventChannelManager->unsubscribeFrom(_moduleName + "/" + elementId + "/" + channelName);
    if(!silent) _subscriptionMap.erase(_moduleName + "/" + elementId + "/" + channelName);
}


SubscriptionHelperExt::SubscriptionHelperExt(std::shared_ptr<EventChannelManager> eventChannelManager, const std::string& moduleName, const std::string& elementName) : 
    _subscriptionHelper(eventChannelManager, moduleName, elementName), _moduleName(moduleName), _elementName(elementName), _map(utils::ThreadSaveMap<std::string, std::string>()) {}

bool SubscriptionHelperExt::hasSubscriptionForElement(const std::string& elementId) {
    return _map.get(_moduleName + "/" + elementId + "/" + _elementName).has_value();
}

bool SubscriptionHelperExt::hasSubscriptionForElementCustom(const std::string& elementId, const std::string&  channelName) {
    return _map.get(_moduleName + "/" + elementId + "/" + channelName).has_value();
}

bool SubscriptionHelperExt::hasSubscriptionForChannel(const std::string& fullChannel) {
    return _map.get(fullChannel).has_value();
}

void SubscriptionHelperExt::subscribeForElement(const std::string& elementId, const std::string& parentModuleId,  bool silent) {
    _subscriptionHelper.subscribeForElement(elementId);
    if(!silent) _map.set(_moduleName + "/" + elementId + "/" + _elementName, parentModuleId);
}

void SubscriptionHelperExt::unsubscribeFromElement(const std::string& elementId, bool silent) {
    _subscriptionHelper.unsubscribeFromElement(elementId);
    if(!silent) _map.erase(_moduleName + "/" + elementId + "/" + _elementName);
}

void SubscriptionHelperExt::subscribeForElementCustom(const std::string& elementId, const std::string& parentModuleId, const std::string&  channelName,  bool silent) {
    _subscriptionHelper.subscribeForElementCustom(elementId, channelName);
    if(!silent) _map.set(_moduleName + "/" + elementId + "/" + channelName, parentModuleId);
}

void SubscriptionHelperExt::unsubscribeFromElementCustom(const std::string& elementId, const std::string&  channelName, bool silent) {
    _subscriptionHelper.unsubscribeFromElementCustom(elementId, channelName);
    if(!silent) _map.erase(_moduleName + "/" + elementId + "/" + channelName);
}

std::string SubscriptionHelperExt::getParentModuleId(const std::string& elementId) {
    auto tmp = _map.get(_moduleName + "/" + elementId + "/" + _elementName);
    return tmp.has_value() ? tmp.value() : std::string();
}