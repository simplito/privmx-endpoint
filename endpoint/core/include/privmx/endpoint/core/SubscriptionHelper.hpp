/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/



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
    SubscriptionHelper(std::shared_ptr<EventChannelManager> eventChannelManager, const std::string& moduleName, const std::string& elementName);
    bool hasSubscriptionForModule();
    bool hasSubscriptionForElement(const std::string& elementId);
    bool hasSubscriptionForElementCustom(const std::string& elementId, const std::string& channelName);
    bool hasSubscriptionForChannel(const std::string& fullChannel);

    void subscribeForModule(bool silent = false);
    void unsubscribeFromModule(bool silent = false);
    void subscribeForElement(const std::string& elementId, bool silent = false);
    void unsubscribeFromElement(const std::string& elementId, bool silent = false);
    void subscribeForElementCustom(const std::string& elementId, const std::string&  channelName, bool silent = false);
    void unsubscribeFromElementCustom(const std::string& elementId, const std::string&  channelName, bool silent = false);
private:
    std::shared_ptr<EventChannelManager> _eventChannelManager;
    std::string _moduleName;
    std::string _elementName;
    bool _moduleFlag;
    utils::ThreadSaveMap<std::string, bool> _subscriptionMap;
};

class SubscriptionHelperExt {
public:
    SubscriptionHelperExt(std::shared_ptr<EventChannelManager> eventChannelManager, const std::string& moduleName, const std::string& elementName);
    bool hasSubscriptionForElement(const std::string& elementId);
    bool hasSubscriptionForElementCustom(const std::string& elementId, const std::string& channelName);
    bool hasSubscriptionForChannel(const std::string& fullChannel);
    std::string getParentModuleId(const std::string& elementId);

    void subscribeForElement(const std::string& elementId, const std::string& parentModuleId, bool silent = false);
    void unsubscribeFromElement(const std::string& elementId, bool silent = false);
    void subscribeForElementCustom(const std::string& elementId, const std::string& parentModuleId, const std::string& channelName, bool silent = false);
    void unsubscribeFromElementCustom(const std::string& elementId, const std::string& channelName, bool silent = false);
private:
    SubscriptionHelper _subscriptionHelper;
    std::string _moduleName;
    std::string _elementName;
    utils::ThreadSaveMap<std::string, std::string> _map;
};


} // core
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_SUBSCRIPTION_HELPER_HPP_