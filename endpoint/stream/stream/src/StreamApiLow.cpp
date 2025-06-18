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

StreamApiLow StreamApiLow::create(const core::Connection& connection, event::EventApi& eventApi) {
    try {
        std::shared_ptr<core::ConnectionImpl> connectionImpl = connection.getImpl();
        std::shared_ptr<event::EventApiImpl> eventApiImpl = eventApi.getImpl();
        std::shared_ptr<StreamApiLowImpl> impl(new StreamApiLowImpl(
            eventApiImpl,
            connection,
            connectionImpl->getGateway(),
            connectionImpl->getUserPrivKey(),
            connectionImpl->getKeyProvider(),
            connectionImpl->getHost(),
            connectionImpl->getEventMiddleware(),
            connectionImpl->getEventChannelManager()
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
    core::Validator::validateClass<core::PagingQuery>(query, "field:query ");
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

int64_t StreamApiLow::createStream(const std::string& streamRoomId, int64_t localStreamId, std::shared_ptr<WebRTCInterface> webRtc) {
    validateEndpoint();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    try {
        return _impl->createStream(streamRoomId, localStreamId, webRtc);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApiLow::publishStream(int64_t localStreamId) {
    validateEndpoint();
    try {
        return _impl->publishStream(localStreamId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

int64_t StreamApiLow::joinStream(const std::string& streamRoomId, const std::vector<int64_t>& streamsId, const Settings& settings, int64_t localStreamId, std::shared_ptr<WebRTCInterface> webRtc) {
    validateEndpoint();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    try {
        return _impl->joinStream(streamRoomId, streamsId, settings, localStreamId, webRtc);
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

void StreamApiLow::unpublishStream(int64_t streamId) {
    validateEndpoint();
    try {
        return _impl->unpublishStream(streamId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApiLow::leaveStream(int64_t streamId) {
    validateEndpoint();
    try {
        return _impl->leaveStream(streamId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApiLow::keyManagement(bool disable) {
    validateEndpoint();
    try {
        return _impl->keyManagement(disable);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApiLow::validateEndpoint() {
    if(!_impl) throw NotInitializedException();
}