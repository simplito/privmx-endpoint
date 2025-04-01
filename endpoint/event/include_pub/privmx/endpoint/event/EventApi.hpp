#ifndef _PRIVMXLIB_ENDPOINT_EVENT_EVENTAPI_HPP_
#define _PRIVMXLIB_ENDPOINT_EVENT_EVENTAPI_HPP_

#include "privmx/endpoint/core/Connection.hpp"
#include "privmx/endpoint/core/Types.hpp"
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
     * @param users list of UserWithPubKey objects which defines the recipeints of the event
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
    void subscribeForCustomEvents(const std::string& contextId, const std::string& channelName);
    
    /**
     * Unsubscribe from the custom events on the given channel.
     * 
     * @param contextId ID of the Context
     * @param channelName name of the Channel
     */
    void unsubscribeFromCustomEvents(const std::string& contextId, const std::string& channelName);

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
