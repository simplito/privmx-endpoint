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

#include "privmx/endpoint/stream/StreamApi.hpp"
#include "privmx/endpoint/stream/StreamException.hpp"
#include "privmx/endpoint/stream/StreamApiImpl.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::stream;

StreamApi StreamApi::create(core::Connection& connection) {
    try {
        std::shared_ptr<core::ConnectionImpl> connectionImpl = connection.getImpl();
        std::shared_ptr<StreamApiImpl> impl(new StreamApiImpl(
            connectionImpl->getGateway(),
            connectionImpl->getUserPrivKey(),
            connectionImpl->getKeyProvider(),
            connectionImpl->getHost(),
            connectionImpl->getEventMiddleware(),
            connectionImpl->getEventChannelManager(),
            connection
        ));
        return StreamApi(impl);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

StreamApi::StreamApi(const std::shared_ptr<StreamApiImpl>& impl) : _impl(impl) {}

std::string StreamApi::roomCreate(
    const std::string& contextId, 
    const std::vector<core::UserWithPubKey>& users, 
    const std::vector<core::UserWithPubKey>&managers,
    const core::Buffer& publicMeta, 
    const core::Buffer& privateMeta,
    const std::optional<core::ContainerPolicy>& policies
) {
    validateEndpoint();
    try {
        return _impl->roomCreate(contextId, users, managers, publicMeta, privateMeta, policies);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApi::roomUpdate(
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
    try {
        return _impl->roomUpdate(streamRoomId, users, managers, publicMeta, privateMeta, version, force, forceGenerateNewKey, policies);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

core::PagingList<StreamRoom> StreamApi::streamRoomList(const std::string& contextId, const core::PagingQuery& query) {
    validateEndpoint();
    try {
        return _impl->streamRoomList(contextId, query);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

StreamRoom StreamApi::streamRoomGet(const std::string& streamRoomId) {
    validateEndpoint();
    try {
        return _impl->streamRoomGet(streamRoomId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApi::streamRoomDelete(const std::string& streamRoomId) {
    validateEndpoint();
    try {
        return _impl->streamRoomDelete(streamRoomId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

int64_t StreamApi::streamCreate(const std::string& streamRoomId, const StreamCreateMeta& meta) {
    validateEndpoint();
    try {
        return _impl->streamCreate(streamRoomId, meta);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApi::streamUpdate(int64_t streamId, const StreamCreateMeta& meta) {
    validateEndpoint();
    try {
        return _impl->streamUpdate(streamId, meta);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

core::PagingList<Stream> StreamApi::streamList(const std::string& streamRoomId, const core::PagingQuery& query) {
    validateEndpoint();
    try {
        return _impl->streamList(streamRoomId, query);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

Stream StreamApi::streamGet(const std::string& streamRoomId, int64_t streamId) {
    validateEndpoint();
    try {
        return _impl->streamGet(streamRoomId, streamId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApi::streamDelete(int64_t streamId) {
    validateEndpoint();
    try {
        return _impl->streamDelete(streamId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::string StreamApi::streamTrackAdd(int64_t streamId, const StreamTrackMeta& meta) {
    validateEndpoint();
    try {
        return _impl->streamTrackAdd(streamId, meta);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApi::streamTrackRemove(const std::string& streamTrackId) {
    validateEndpoint();
    try {
        return _impl->streamTrackRemove(streamTrackId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

List<TrackInfo> StreamApi::streamTrackList(const std::string& streamRoomId, int64_t streamId) {
    validateEndpoint();
    try {
        return _impl->streamTrackList(streamRoomId, streamId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApi::streamTrackSendData(const std::string& streamTrackId, const core::Buffer& data) {
    validateEndpoint();
    try {
        return _impl->streamTrackSendData(streamTrackId, data);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApi::streamTrackRecvData(const std::string& streamTrackId, std::function<void(const core::Buffer& type)> onData) {
    validateEndpoint();
    try {
        return _impl->streamTrackRecvData(streamTrackId, onData);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApi::streamPublish(int64_t streamId) {
    validateEndpoint();
    try {
        return _impl->streamPublish(streamId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApi::streamUnpublish(int64_t streamId) {
    validateEndpoint();
    try {
        return _impl->streamUnpublish(streamId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApi::validateEndpoint() {
    if(!_impl) throw NotInitializedException();
}