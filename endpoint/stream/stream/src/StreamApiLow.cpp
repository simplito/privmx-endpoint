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
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/EventVarSerializer.hpp>
#include <privmx/endpoint/core/Validator.hpp>
#include <privmx/endpoint/event/EventApiImpl.hpp>

#include "privmx/endpoint/stream/StreamApiLow.hpp"
#include "privmx/endpoint/stream/StreamException.hpp"
#include "privmx/endpoint/stream/StreamApiLowImpl.hpp"


using namespace privmx::endpoint;
using namespace privmx::endpoint::stream;

StreamApiLow StreamApiLow::create(
    const core::Connection& connection, 
    event::EventApi& eventApi
) {
    try {
        std::shared_ptr<core::ConnectionImpl> connectionImpl = connection.getImpl();
        std::shared_ptr<event::EventApiImpl> eventApiImpl = eventApi.getImpl();
        std::shared_ptr<StreamApiLowImpl> impl(new stream::StreamApiLowImpl(
            eventApiImpl,
            connection,
            connectionImpl->getGateway(),
            connectionImpl->getUserPrivKey(),
            connectionImpl->getKeyProvider(),
            connectionImpl->getHost(),
            connectionImpl->getEventMiddleware()
        ));
        return StreamApiLow(impl);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

StreamApiLow::StreamApiLow(const std::shared_ptr<StreamApiLowImpl>& impl) : _impl(impl) {}

std::vector<TurnCredentials> StreamApiLow::getTurnCredentials() {
    validateEndpoint();
    try {
        return _impl->getTurnCredentials();
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::string StreamApiLow::createStreamRoom(
    const std::string& contextId, 
    const std::vector<core::UserWithPubKey>& users, 
    const std::vector<core::UserWithPubKey>&managers,
    const core::Buffer& publicMeta, 
    const core::Buffer& privateMeta,
    const std::optional<core::ContainerPolicy>& policies
) {
    validateEndpoint();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    try {
        return _impl->createStreamRoom(contextId, users, managers, publicMeta, privateMeta, policies);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApiLow::updateStreamRoom(
    const std::string& streamRoomId, 
    const std::vector<core::UserWithPubKey>& users, 
    const std::vector<core::UserWithPubKey>&managers,
    const core::Buffer& publicMeta, 
    const core::Buffer& privateMeta, 
    const int64_t version, 
    const bool force, 
    const bool forceGenerateNewKey, 
    const std::optional<core::ContainerPolicy>& policies
) {
    validateEndpoint();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    try {
        return _impl->updateStreamRoom(streamRoomId, users, managers, publicMeta, privateMeta, version, force, forceGenerateNewKey, policies);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

core::PagingList<StreamRoom> StreamApiLow::listStreamRooms(const std::string& contextId, const core::PagingQuery& query) {
    validateEndpoint();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validatePagingQuery(query, {"createDate"}, "field:query ");
    try {
        return _impl->listStreamRooms(contextId, query);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}   

StreamRoom StreamApiLow::getStreamRoom(const std::string& streamRoomId) {
    validateEndpoint();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    try {
        return _impl->getStreamRoom(streamRoomId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApiLow::deleteStreamRoom(const std::string& streamRoomId) {
    validateEndpoint();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    try {
        return _impl->deleteStreamRoom(streamRoomId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::vector<std::string> StreamApiLow::subscribeFor(const std::vector<std::string>& subscriptionQueries) {
    validateEndpoint();
    try {
        return _impl->subscribeFor(subscriptionQueries);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApiLow::unsubscribeFrom(const std::vector<std::string>& subscriptionIds) {
    validateEndpoint();
    try {
        return _impl->unsubscribeFrom(subscriptionIds);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::string StreamApiLow::buildSubscriptionQuery(EventType eventType, EventSelectorType selectorType, const std::string& selectorId) {
    validateEndpoint();
    try {
        return _impl->buildSubscriptionQuery(eventType, selectorType, selectorId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::vector<Stream> StreamApiLow::listStreams(const std::string& streamRoomId) {
    validateEndpoint();
    try {
        return _impl->listStreams(streamRoomId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApiLow::joinStreamRoom(const std::string& streamRoomId, std::shared_ptr<WebRTCInterface> webRtc) {
    validateEndpoint();
    try {
        return _impl->joinStreamRoom(streamRoomId, webRtc);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApiLow::leaveStreamRoom(const std::string& streamRoomId) {
    validateEndpoint();
    try {
        return _impl->leaveStreamRoom(streamRoomId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

StreamHandle StreamApiLow::createStream(const std::string& streamRoomId) {
    validateEndpoint();
    try {
        return _impl->createStream(streamRoomId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

RemoteStreamId StreamApiLow::publishStream(const StreamHandle& streamHandle) {
    validateEndpoint();
    try {
        return _impl->publishStream(streamHandle);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApiLow::unpublishStream(const StreamHandle& streamHandle) {
    validateEndpoint();
    try {
        return _impl->unpublishStream(streamHandle);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApiLow::subscribeToRemoteStreams(const std::string& streamRoomId, const std::vector<StreamSubscription>& subscriptions, const Settings& options) {
    validateEndpoint();
    try {
        return _impl->subscribeToRemoteStreams(streamRoomId, subscriptions, options);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApiLow::modifyRemoteStreamsSubscriptions(const std::string& streamRoomId, const std::vector<StreamSubscription>& subscriptionsToAdd, const std::vector<StreamSubscription>& subscriptionsToRemove, const Settings& options) {
    validateEndpoint();
    try {
        return _impl->modifyRemoteStreamsSubscriptions(streamRoomId, subscriptionsToAdd, subscriptionsToRemove, options);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApiLow::unsubscribeFromRemoteStreams(const std::string& streamRoomId, const std::vector<StreamSubscription>& subscriptionsToRemove) {
    validateEndpoint();
    try {
        return _impl->unsubscribeFromRemoteStreams(streamRoomId, subscriptionsToRemove);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApiLow::keyManagement(const std::string& streamRoomId, bool disable) {
    validateEndpoint();
    try {
        return _impl->keyManagement(streamRoomId, disable);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApiLow::validateEndpoint() {
    if(!_impl) throw NotInitializedException();
}

void StreamApiLow::trickle(const int64_t sessionId, const std::string& candidateAsJson) {
    validateEndpoint();
    core::Validator::validateNumberPositive(sessionId, "field:sessionId ");
    try {
        return _impl->trickle(sessionId, candidateAsJson);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApiLow::acceptOfferOnReconfigure(const int64_t sessionId, const SdpWithTypeModel& sdp) {
    validateEndpoint();
    core::Validator::validateNumberPositive(sessionId, "field:sessionId ");
    try {
        return _impl->acceptOfferOnReconfigure(sessionId, sdp);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}
