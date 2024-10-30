

#ifndef _PRIVMXLIB_ENDPOINT_CORE_SUBSCRIPTION_HELPER_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_SUBSCRIPTION_HELPER_HPP_

#include <string>
#include <privmx/utils/ThreadSaveMap.hpp>
#include "privmx/endpoint/core/EventChannelManager.hpp"

namespace privmx {
namespace endpoint {
namespace core {

class SubscriptionHelper {
public:
    SubscriptionHelper(std::shared_ptr<EventChannelManager> eventChannelManager, const std::string moduleName, const std::string elementName);
    bool hasSubscriptionForModule();
    bool hasSubscriptionForElement(std::string elementId);

    void subscribeForModule();
    void unsubscribeFromModule();
    void subscribeForElement(std::string elementId);
    void unsubscribeFromElement(std::string elementId);
private:
    std::shared_ptr<EventChannelManager> _eventChannelManager;
    std::string _moduleName;
    std::string _elementName;
    bool _moduleFlag;
    utils::ThreadSaveMap<std::string, bool> _map;
};

class SubscriptionHelperExt {
public:
    SubscriptionHelperExt(std::shared_ptr<EventChannelManager> eventChannelManager, const std::string moduleName, const std::string elementName);
    bool hasSubscriptionForElement(std::string elementId);
    std::string getParentModuleId(std::string elementId);

    void subscribeForElement(std::string elementId, std::string parentModuleId);
    void unsubscribeFromElement(std::string elementId);
private:
    SubscriptionHelper _subscriptionHelper;
    utils::ThreadSaveMap<std::string, std::string> _map;
};


} // core
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_SUBSCRIPTION_HELPER_HPP_