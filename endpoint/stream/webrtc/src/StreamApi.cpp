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
#include <privmx/endpoint/core/EventVarSerializer.hpp>
#include <privmx/endpoint/core/Validator.hpp>
#include <privmx/endpoint/event/EventApi.hpp>
#include "privmx/endpoint/stream/StreamApi.hpp"
#include "privmx/endpoint/stream/StreamException.hpp"
#include "privmx/endpoint/stream/StreamApiImpl.hpp"


using namespace privmx::endpoint;
using namespace privmx::endpoint::stream;

StreamApi StreamApi::create(core::Connection& connection, event::EventApi& eventApi) {
    try {
        std::shared_ptr<StreamApiImpl> impl(new StreamApiImpl(
            connection,
            eventApi
        ));
        return StreamApi(impl);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

StreamApi::StreamApi(const std::shared_ptr<StreamApiImpl>& impl) : _impl(impl) {}

std::string StreamApi::createStreamRoom(
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

void StreamApi::updateStreamRoom(
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

core::PagingList<StreamRoom> StreamApi::listStreamRooms(const std::string& contextId, const core::PagingQuery& query) {
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

StreamRoom StreamApi::getStreamRoom(const std::string& streamRoomId) {
    validateEndpoint();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    try {
        return _impl->getStreamRoom(streamRoomId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApi::deleteStreamRoom(const std::string& streamRoomId) {
    validateEndpoint();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    try {
        return _impl->deleteStreamRoom(streamRoomId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::vector<Stream> StreamApi::listStreams(const std::string& streamRoomId) {
    validateEndpoint();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    try {
        return _impl->listStreams(streamRoomId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApi::joinRoom(const std::string& streamRoomId) {
    validateEndpoint();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    try {
        return _impl->joinRoom(streamRoomId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApi::leaveRoom(const std::string& streamRoomId) {
    validateEndpoint();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    try {
        return _impl->leaveRoom(streamRoomId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

StreamHandle StreamApi::createStream(const std::string& streamRoomId) {
    validateEndpoint();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    try {
        return _impl->createStream(streamRoomId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::vector<MediaDevice> StreamApi::getMediaDevices() {
    validateEndpoint();
    try {
        return _impl->getMediaDevices();
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApi::addTrack(const StreamHandle& streamHandle, const MediaDevice& track) {
    validateEndpoint();
    try {
        return _impl->addTrack(streamHandle, track);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApi::removeTrack(const StreamHandle& streamHandle, const MediaDevice& track) {
    validateEndpoint();
    try {
        return _impl->removeTrack(streamHandle, track);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

RemoteStreamId StreamApi::publishStream(const StreamHandle& streamHandle) {
    validateEndpoint();
    try {
        return _impl->publishStream(streamHandle);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApi::unpublishStream(const std::string& streamRoomId, const RemoteStreamId& streamId) {
    validateEndpoint();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    try {
        return _impl->unpublishStream(streamRoomId, streamId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApi::openRemoteStream(const std::string& streamRoomId, const RemoteStreamId& streamId, const std::optional<std::vector<RemoteTrackId>>& tracksIds, const StreamSettings& options) {
    validateEndpoint();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    try {
        return _impl->openRemoteStream(streamRoomId, streamId, tracksIds, options);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApi::openRemoteStreams(const std::string& streamRoomId, const std::vector<RemoteStreamId>& streamId, const StreamSettings& options) {
    validateEndpoint();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    try {
        return _impl->openRemoteStreams(streamRoomId, streamId, options);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApi::modifyRemoteStream(const std::string& streamRoomId, const RemoteStreamId& streamId, const StreamSettings& options, const std::optional<std::vector<RemoteTrackId>>& tracksIdsToAdd, const std::optional<std::vector<RemoteTrackId>>& tracksIdsToRemove) {
    validateEndpoint();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    try {
        return _impl->modifyRemoteStream(streamRoomId, streamId, options, tracksIdsToAdd, tracksIdsToRemove);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApi::closeRemoteStream(const std::string& streamRoomId, const RemoteStreamId& streamId) {
    validateEndpoint();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    try {
        return _impl->closeRemoteStream(streamRoomId, streamId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApi::closeRemoteStreams(const std::string& streamRoomId, const std::vector<RemoteStreamId>& streamsIds) {
    validateEndpoint();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    try {
        return _impl->closeRemoteStreams(streamRoomId, streamsIds);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::vector<std::string> StreamApi::subscribeFor(const std::vector<std::string>& subscriptionQueries) {
    validateEndpoint();
    try {
        return _impl->subscribeFor(subscriptionQueries);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApi::unsubscribeFrom(const std::vector<std::string>& subscriptionIds) {
    validateEndpoint();
    try {
        return _impl->unsubscribeFrom(subscriptionIds);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::string StreamApi::buildSubscriptionQuery(EventType eventType, EventSelectorType selectorType, const std::string& selectorId) {
    validateEndpoint();
    try {
        return _impl->buildSubscriptionQuery(eventType, selectorType, selectorId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApi::dropBrokenFrames(const std::string& streamRoomId, bool enable) {
    validateEndpoint();
    try {
        return _impl->dropBrokenFrames(streamRoomId, enable);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApi::validateEndpoint() {
    if(!_impl) throw NotInitializedException();
}