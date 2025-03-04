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
    core::Validator::validateClass<core::PagingQuery>(query, "field:query ");
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

int64_t StreamApi::createStream(const std::string& streamRoomId) {
    validateEndpoint();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    try {
        return _impl->createStream(streamRoomId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::vector<std::pair<int64_t, std::string>> StreamApi::listAudioRecordingDevices() {
    validateEndpoint();
    try {
        return _impl->listAudioRecordingDevices();
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }   
}

std::vector<std::pair<int64_t, std::string>> StreamApi::listVideoRecordingDevices() {
    validateEndpoint();
    try {
        return _impl->listVideoRecordingDevices();
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::vector<std::pair<int64_t, std::string>> StreamApi::listDesktopRecordingDevices() {
    validateEndpoint();
    try {
        return _impl->listDesktopRecordingDevices();
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApi::trackAdd(int64_t streamId, DeviceType type, int64_t id, const std::string& params_JSON) {
    validateEndpoint();
    try {
        return _impl->trackAdd(streamId, type, id, params_JSON);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApi::publishStream(int64_t streamId) {
    validateEndpoint();
    try {
        return _impl->publishStream(streamId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

int64_t StreamApi::joinStream(const std::string& streamRoomId, const std::vector<int64_t>& streamsId, const StreamJoinSettings& settings) {
    validateEndpoint();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    try {
        return _impl->joinStream(streamRoomId, streamsId, settings);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::vector<Stream> StreamApi::listStreams(const std::string& streamRoomId) {
    validateEndpoint();
    try {
        return _impl->listStreams(streamRoomId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApi::unpublishStream(int64_t streamId) {
    validateEndpoint();
    try {
        return _impl->unpublishStream(streamId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApi::leaveStream(int64_t streamId) {
    validateEndpoint();
    try {
        return _impl->leaveStream(streamId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApi::keyManagement(bool disable) {
    validateEndpoint();
    try {
        return _impl->keyManagement(disable);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApi::dropBrokenFrames(bool enable) {
    validateEndpoint();
    try {
        return _impl->dropBrokenFrames(enable);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApi::validateEndpoint() {
    if(!_impl) throw NotInitializedException();
}