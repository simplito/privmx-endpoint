#ifndef _PRIVMXLIB_ENDPOINT_EVENT_EVENTAPI_HPP_
#define _PRIVMXLIB_ENDPOINT_EVENT_EVENTAPI_HPP_

#include "privmx/endpoint/core/Connection.hpp"
#include "privmx/endpoint/event/Types.hpp"
#include "privmx/endpoint/core/Buffer.hpp"

namespace privmx {
namespace endpoint {
namespace event {

class EventApiImpl;

/**
 * 'EventApi' is a class representing Endpoint's API for context custom events.
 */
class EventApi {
public:

    /**
     * Creates an instance of 'EventApi'.
     * 
     * @param connection instance of 'Connection'
     * 
     * @return EventApi object
     */
    static EventApi create(core::Connection& connection);
    EventApi() = default;

    /**
     * Emits the custom event on the given Context and channel.
     * 
     * @param contextId ID of the Context
     * @param users list of UserWithPubKey objects which defines the recipients of the event
     * @param channelName name of the Channel
     * @param eventData event's data
     */
    void emitEvent(const std::string& contextId, const std::vector<core::UserWithPubKey>& users, const std::string& channelName, const core::Buffer& eventData);
    
    /**
     * Subscribe for the custom events on the given channel.
     * 
     * @param contextId ID of the Context
     * @param channelName name of the Channel
     */
    [[deprecated("Use subscribeFor(const std::vector<std::string>& subscriptionQueries).")]]
    void subscribeForCustomEvents(const std::string& contextId, const std::string& channelName);
    
    /**
     * Unsubscribe from the custom events on the given channel.
     * 
     * @param contextId ID of the Context
     * @param channelName name of the Channel
     */
    [[deprecated("Use unsubscribeFrom(const std::vector<std::string>& subscriptionIds).")]]
    void unsubscribeFromCustomEvents(const std::string& contextId, const std::string& channelName);

    /**
     * Subscribe for the custom events on the given subscription query.
     * 
     * @param subscriptionQueries list of queries
     * @return list of subscriptionIds in maching order to subscriptionQueries
     */
    std::vector<std::string> subscribeFor(const std::vector<std::string>& subscriptionQueries);

    /**
     * Unsubscribe from events for the given subscriptionId.
     * @param subscriptionIds list of subscriptionId
     */
    void unsubscribeFrom(const std::vector<std::string>& subscriptionIds);

    /**
     * Generate subscription Query for the custom events.
     * @param channelName name of the Channel
     * @param selectorType selector of scope on which you listen for events  
     * @param selectorId ID of the selector
     */
    std::string buildSubscriptionQuery(const std::string& channelName, EventSelectorType selectorType, const std::string& selectorId);

    std::shared_ptr<EventApiImpl> getImpl() const { return _impl; }
private:
    void validateEndpoint();
    EventApi(const std::shared_ptr<EventApiImpl>& impl);
    std::shared_ptr<EventApiImpl> _impl;
};

}  // namespace event
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_EVENT_EVENTAPI_HPP_
