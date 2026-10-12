/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/endpoint/core/JsonSerializer.hpp>
#include <privmx/endpoint/core/Validator.hpp>

#include "privmx/endpoint/event/EventApi.hpp"
#include "privmx/endpoint/event/EventApiImpl.hpp"
#include "privmx/endpoint/event/EventException.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::event;

EventApi EventApi::create(core::Connection& connection) {
    std::shared_ptr<core::ConnectionImpl> connectionImpl = connection.getImpl();
    std::shared_ptr<EventApiImpl> impl(new EventApiImpl(
        connection, connectionImpl->getUserPrivKey(), connectionImpl->getGateway(),
        connectionImpl->getEventMiddleware()
    ));
    return EventApi(impl);
}

EventApi::EventApi(const std::shared_ptr<EventApiImpl>& impl) : BaseApiClass(impl) {}

void EventApi::emitEvent(
    const std::string& contextId,
    const std::vector<core::UserWithPubKey>& users,
    const std::string& channelName,
    const core::Buffer& eventData
) {
    auto impl = getImpl();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    return impl->emitEvent(contextId, users, channelName, eventData);
}

std::vector<std::string> EventApi::subscribeFor(const std::vector<std::string>& subscriptionQueries) {
    return getImpl()->subscribeFor(subscriptionQueries);
}

void EventApi::unsubscribeFrom(const std::vector<std::string>& subscriptionIds) {
    return getImpl()->unsubscribeFrom(subscriptionIds);
}

std::string EventApi::buildSubscriptionQuery(
    const std::string& channelName,
    EventSelectorType selectorType,
    const std::string& selectorId
) {
    return getImpl()->buildSubscriptionQuery(channelName, selectorType, selectorId);
}
