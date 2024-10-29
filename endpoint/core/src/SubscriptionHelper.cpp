#include "privmx/endpoint/core/SubscriptionHelper.hpp"

using namespace privmx::endpoint::core;


SubscriptionHelper::SubscriptionHelper(std::shared_ptr<EventChannelManager> eventChannelManager, const std::string moduleName, const std::string elementName) : 
    _eventChannelManager(eventChannelManager), _moduleName(moduleName), _elementName(elementName),_moduleFlag(false), _map(utils::ThreadSaveMap<std::string, bool>()) {}

bool SubscriptionHelper::hasSubscriptionForModule() {
    return _moduleFlag;
}

bool SubscriptionHelper::hasSubscriptionForElement(std::string elementId) {
    return _map.get(elementId).has_value();
}

void SubscriptionHelper::subscribeForModule() {
    _eventChannelManager->subscribeFor(_moduleName);
    _moduleFlag = true;
}

void SubscriptionHelper::unsubscribeFromModule() {
    _eventChannelManager->unsubscribeFrom(_moduleName);
    _moduleFlag = false;
}

void SubscriptionHelper::subscribeForElement(std::string elementId) {
    _eventChannelManager->subscribeFor(_moduleName + "/" + elementId + "/" + _elementName);
    _map.set(elementId, true);
}

void SubscriptionHelper::unsubscribeFromElement(std::string elementId) {
    _eventChannelManager->unsubscribeFrom(_moduleName + "/" + elementId + "/" + _elementName);
    _map.erase(elementId);
}


SubscriptionHelperExt::SubscriptionHelperExt(std::shared_ptr<EventChannelManager> eventChannelManager, const std::string moduleName, const std::string elementName) : 
    _subscriptionHelper(eventChannelManager, moduleName, elementName), _map(utils::ThreadSaveMap<std::string, std::string>()) {}

bool SubscriptionHelperExt::hasSubscriptionForElement(std::string elementId) {
    return _map.get(elementId).has_value();
}

void SubscriptionHelperExt::subscribeForElement(std::string elementId, std::string parentModuleId) {
    _subscriptionHelper.subscribeForElement(elementId);
    _map.set(elementId, parentModuleId);
}

void SubscriptionHelperExt::unsubscribeFromElement(std::string elementId) {
    _subscriptionHelper.unsubscribeFromElement(elementId);
    _map.erase(elementId);
}

std::string SubscriptionHelperExt::getParentModuleId(std::string elementId) {
    auto tmp = _map.get(elementId);
    return tmp.has_value() ? tmp.value() : std::string();
}