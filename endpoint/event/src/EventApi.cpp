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

EventApi::EventApi() {};
EventApi::EventApi(const EventApi& obj): _impl(obj._impl) {
    attachToImplIfPossible();
};
EventApi& EventApi::operator=(const EventApi& obj) {
    _impl = obj._impl;
    attachToImplIfPossible();
    return *this;
};
EventApi::EventApi(EventApi&& obj): _impl(obj._impl) {
    attachToImplIfPossible();
};
EventApi::~EventApi() {
    detachFromImplIfPossible();
}

EventApi EventApi::create(core::Connection& connection) {
    try {
        std::shared_ptr<core::ConnectionImpl> connectionImpl = connection.getImpl();
        std::shared_ptr<EventApiImpl> impl(new EventApiImpl(
            connection,
            connectionImpl->getUserPrivKey(),
            connectionImpl->getGateway(),
            connectionImpl->getEventMiddleware()
        ));
        impl->attach(impl);
        return EventApi(impl);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

EventApi::EventApi(const std::shared_ptr<EventApiImpl>& impl) : _impl(impl) {}

std::shared_ptr<EventApiImpl> EventApi::getImpl() const { 
    auto impl = _impl.lock();
    if(!impl) throw NotInitializedException();
    return impl; 
}

void EventApi::attachToImplIfPossible() {
    if(!_impl.expired()) {
        auto impl = _impl.lock();
        if(impl) {
            impl->attach();
        }
    }
};

void EventApi::detachFromImplIfPossible() {
    if(!_impl.expired()) {
        auto impl = _impl.lock();
        if(impl) {
            impl->detach();
        }
    }
}

void EventApi::emitEvent(const std::string& contextId, const std::vector<core::UserWithPubKey>& users, const std::string& channelName, const core::Buffer& eventData) {
    auto impl = getImpl();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    try {
        return impl->emitEvent(contextId, users, channelName, eventData);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::vector<std::string> EventApi::subscribeFor(const std::vector<std::string>& subscriptionQueries) {
    auto impl = getImpl();
    try {
        return impl->subscribeFor(subscriptionQueries);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void EventApi::unsubscribeFrom(const std::vector<std::string>& subscriptionIds) {
    auto impl = getImpl();
    try {
        return impl->unsubscribeFrom(subscriptionIds);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::string EventApi::buildSubscriptionQuery(const std::string& channelName, EventSelectorType selectorType, const std::string& selectorId) {
    auto impl = getImpl();
    try {
        return impl->buildSubscriptionQuery(channelName, selectorType, selectorId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

