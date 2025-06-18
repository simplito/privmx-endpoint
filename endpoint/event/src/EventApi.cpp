/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/endpoint/core/JsonSerializer.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/endpoint/core/Validator.hpp>
#include <privmx/endpoint/core/ConnectionImpl.hpp>

#include "privmx/endpoint/event/EventApi.hpp"
#include "privmx/endpoint/event/EventException.hpp"
#include "privmx/endpoint/event/EventApiImpl.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::event;

EventApi EventApi::create(core::Connection& connection) {
    try {
        std::shared_ptr<core::ConnectionImpl> connectionImpl = connection.getImpl();
        std::shared_ptr<EventApiImpl> impl(new EventApiImpl(
            connectionImpl->getUserPrivKey(),
            connectionImpl->getGateway(),
            connectionImpl->getEventMiddleware(),
            connectionImpl->getEventChannelManager()
        ));
        return EventApi(impl);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}


EventApi::EventApi(const std::shared_ptr<EventApiImpl>& impl) : _impl(impl) {}

void EventApi::emitEvent(const std::string& contextId, const std::vector<core::UserWithPubKey>& users, const std::string& channelName, const core::Buffer& eventData) {
    validateEndpoint();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    try {
        return _impl->emitEvent(contextId, users, channelName, eventData);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void EventApi::subscribeForCustomEvents(const std::string& contextId, const std::string& channelName) {
    validateEndpoint();
    core::Validator::validateId(contextId, "field:contextId ");
    try {
        return _impl->subscribeForCustomEvents(contextId, channelName);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void EventApi::unsubscribeFromCustomEvents(const std::string& contextId, const std::string& channelName) {
    validateEndpoint();
    core::Validator::validateId(contextId, "field:contextId ");
    try {
        return _impl->unsubscribeFromCustomEvents(contextId, channelName);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void EventApi::validateEndpoint() {
    if(!_impl) throw NotInitializedException();
}

