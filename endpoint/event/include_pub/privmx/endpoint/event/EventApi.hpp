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

    static EventApi create(core::Connection& connection);
    EventApi() = default;

    void emitEvent(const std::string& contextId, const std::string& channelName, const core::Buffer& eventData, const std::vector<core::UserWithPubKey>& users);
    void subscribeForCustomEvents(const std::string& contextId, const std::string& channelName);
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
