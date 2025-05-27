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
    SubscriptionHelper(
        std::shared_ptr<EventChannelManager> eventChannelManager, 
        const std::string& moduleName, 
        const std::string& entryName = "item"
    );
    bool hasSubscriptionForModule();
    bool hasSubscriptionForModuleEntry(const std::string& moduleId);
    bool hasSubscriptionForModuleEntryCustomChannel(const std::string& moduleId, const std::string& channelName);
    bool hasSubscriptionForChannel(const std::string& fullChannel);
    bool hasSubscription(const std::vector<std::string>& subscriptionIds);
    std::string getChannel(const std::vector<std::string>& subscriptionIds);

    void subscribeForModule();
    void unsubscribeFromModule();
    void subscribeForModuleEntry(const std::string& moduleId);
    void unsubscribeFromModuleEntry(const std::string& moduleId);
    void subscribeForModuleEntryCustomChannel(const std::string& moduleId, const std::string&  channelName);
    void unsubscribeFromModuleEntryCustomChannel(const std::string& moduleId, const std::string&  channelName);
    
private:
    std::string getModuleEntryChannel(const std::string& moduleId);
    std::string getModuleEntryCustomChannel(const std::string& moduleId, const std::string& channelName);
    void subscribeFor(const std::string& channel);
    void unsubscribeFor(const std::string& channel);

    std::shared_ptr<EventChannelManager> _eventChannelManager;
    std::string _moduleName;
    std::string _entryName;
    // fast search
    utils::ThreadSaveMap<std::string, std::string> _channelSubscriptionMap; // channel -> subscriptionId 
    utils::ThreadSaveMap<std::string, std::string> _subscriptionMap;        // subscriptionId -> channel
};

class SubscriptionHelperExt {
public:
    SubscriptionHelperExt(
        std::shared_ptr<EventChannelManager> eventChannelManager, 
        const std::string& moduleName, 
        const std::string& entryName = "item"
    );
    bool hasSubscriptionForModuleEntry(const std::string& moduleId);
    bool hasSubscriptionForModuleEntryCustomChannel(const std::string& moduleId, const std::string& channelName);
    bool hasSubscriptionForChannel(const std::string& fullChannel);
    bool hasSubscription(const std::vector<std::string>& subscriptionIds);
    std::string getChannel(const std::vector<std::string>& subscriptionIds);
    std::string getParentModuleEntryId(const std::string& moduleId);

    void subscribeForModuleEntry(const std::string& moduleId, const std::string& parentModuleEntryId);
    void unsubscribeFromModuleEntry(const std::string& moduleId);
    void subscribeForModuleEntryCustomChannel(const std::string& moduleId, const std::string& parentModuleEntryId, const std::string& channelName);
    void unsubscribeFromModuleEntryCustomChannel(const std::string& moduleId, const std::string& channelName);
private:
    std::string getModuleEntryChannel(const std::string& moduleId);
    std::string getModuleEntryCustomChannel(const std::string& moduleId, const std::string& channelName);
    void subscribeFor(const std::string& channel);
    void unsubscribeFor(const std::string& channel);

    SubscriptionHelper _subscriptionHelper;
    std::string _moduleName;
    std::string _entryName;
    utils::ThreadSaveMap<std::string, std::string> _map;
};


} // core
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_SUBSCRIPTION_HELPER_HPP_