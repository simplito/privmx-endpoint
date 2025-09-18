/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_KVDB_SUBSCRIBERIMPL_HPP_
#define _PRIVMXLIB_ENDPOINT_KVDB_SUBSCRIBERIMPL_HPP_

#include <privmx/endpoint/core/Subscriber.hpp>
#include "privmx/endpoint/kvdb/Types.hpp"

namespace privmx {
namespace endpoint {
namespace kvdb {



class SubscriberImpl : public privmx::endpoint::core::Subscriber
{
public:
    
    SubscriberImpl(privmx::privfs::RpcGateway::Ptr gateway, std::string typeFilterFlag) : Subscriber(gateway), _typeFilterFlag(typeFilterFlag) {}
    static std::string buildQuery(EventType eventType, EventSelectorType selectorType, const std::string& selectorId);
    static std::string buildQueryForSelectedEntry(EventType eventType, const std::string& kvdbId, const std::string& kvdbEntryId);

private:
    enum EventInternalSelectorType: int64_t{
        CONTEXT_ID = 0,
        KVDB_ID = 1,
        ENTRY_ID = 2
    };
    virtual privmx::utils::List<std::string> transform(const std::vector<std::string>& subscriptionQueries);
    virtual void assertQuery(const std::vector<std::string>& subscriptionQueries);;

    std::string _typeFilterFlag;
    static std::string getChannel(EventType eventType);
    static std::string getSelector(EventInternalSelectorType selectorType, const std::string& selectorId, const std::optional<std::string>& extraSelectorData = std::nullopt);
    static constexpr std::string_view _moduleName = "kvdb";
    static constexpr std::string_view _itemName = "entries";
    static const std::map<EventInternalSelectorType, std::string> _selectorTypeNames;
    static const std::map<EventType, std::string> _eventTypeNames;
    static const std::map<EventType, std::set<EventInternalSelectorType>> _eventTypeAllowedSelectorTypes;
    static const std::map<EventInternalSelectorType, std::string> _readableSelectorType;
    static const std::map<EventType, std::string> _readableEventType;
};

} // kvdb
} // endpoint
} // privmx


#endif  // _PRIVMXLIB_ENDPOINT_KVDB_SUBSCRIBERIMPL_HPP_
