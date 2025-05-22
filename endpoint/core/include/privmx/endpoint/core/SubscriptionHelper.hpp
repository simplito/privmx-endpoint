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

    void subscribeForModule(bool silent = false);
    void unsubscribeFromModule(bool silent = false);
    void subscribeForModuleEntry(const std::string& moduleId, bool silent = false);
    void unsubscribeFromModuleEntry(const std::string& moduleId, bool silent = false);
    void subscribeForModuleEntryCustomChannel(const std::string& moduleId, const std::string&  channelName, bool silent = false);
    void unsubscribeFromModuleEntryCustomChannel(const std::string& moduleId, const std::string&  channelName, bool silent = false);
    
private:
    std::string getModuleEntryChannel(const std::string& moduleId);
    std::string getModuleEntryCustomChannel(const std::string& moduleId, const std::string& channelName);
    void subscribeFor(const std::string& channel, bool silent);
    void unsubscribeFor(const std::string& channel, bool silent);

    std::shared_ptr<EventChannelManager> _eventChannelManager;
    std::string _moduleName;
    std::string _entryName;
    utils::ThreadSaveMap<std::string, bool> _subscriptionMap;
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
    std::string getParentModuleEntryId(const std::string& moduleId);

    void subscribeForModuleEntry(const std::string& moduleId, const std::string& parentModuleEntryId, bool silent = false);
    void unsubscribeFromModuleEntry(const std::string& moduleId, bool silent = false);
    void subscribeForModuleEntryCustomChannel(const std::string& moduleId, const std::string& parentModuleEntryId, const std::string& channelName, bool silent = false);
    void unsubscribeFromModuleEntryCustomChannel(const std::string& moduleId, const std::string& channelName, bool silent = false);
private:
    std::string getModuleEntryChannel(const std::string& moduleId);
    std::string getModuleEntryCustomChannel(const std::string& moduleId, const std::string& channelName);
    void subscribeFor(const std::string& channel, bool silent);
    void unsubscribeFor(const std::string& channel, bool silent);

    SubscriptionHelper _subscriptionHelper;
    std::string _moduleName;
    std::string _entryName;
    utils::ThreadSaveMap<std::string, std::string> _map;
};


} // core
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_SUBSCRIPTION_HELPER_HPP_