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

#include "privmx/endpoint/stream/StreamApiImpl.hpp"
#include "privmx/endpoint/stream/StreamException.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::stream;

StreamApiImpl::StreamApiImpl(
    const privfs::RpcGateway::Ptr& gateway,
    const privmx::crypto::PrivateKey& userPrivKey,
    const std::shared_ptr<core::KeyProvider>& keyProvider,
    const std::string& host,
    const std::shared_ptr<core::EventMiddleware>& eventMiddleware,
    const std::shared_ptr<core::EventChannelManager>& eventChannelManager,
    const core::Connection& connection
) : _gateway(gateway),
    _userPrivKey(userPrivKey),
    _keyProvider(keyProvider),
    _host(host),
    _eventMiddleware(eventMiddleware),
    _connection(connection),
    _serverApi(ServerApi(gateway)) {}

int64_t StreamApiImpl::roomCreate(
    const std::string& contextId, 
    const std::vector<core::UserWithPubKey>& users, 
    const std::vector<core::UserWithPubKey>&managers,
    const core::Buffer& publicMeta, 
    const core::Buffer& privateMeta
) {
    throw NotImplementedException();
}

void StreamApiImpl::roomUpdate(
    const int64_t& streamRoomId, 
    const std::vector<core::UserWithPubKey>& users, 
    const std::vector<core::UserWithPubKey>&managers,
    const core::Buffer& publicMeta, 
    const core::Buffer& privateMeta
) {
    throw NotImplementedException();
}

core::PagingList<VideoRoom> StreamApiImpl::streamRoomList(const std::string& contextId, const core::PagingQuery& query) {
    throw NotImplementedException();
}

VideoRoom StreamApiImpl::streamRoomGet(int64_t streamRoomId) {
    throw NotImplementedException();
}

void StreamApiImpl::streamRoomDelete(int64_t streamRoomId) {
    throw NotImplementedException();
}

int64_t StreamApiImpl::streamCreate(int64_t streamRoomId, const StreamCreateMeta& meta) {
    throw NotImplementedException();
}

void StreamApiImpl::streamUpdate(int64_t streamId, const StreamCreateMeta& meta) {
    throw NotImplementedException();
}

core::PagingList<Stream> StreamApiImpl::streamList(int64_t streamRoomId, const core::PagingQuery& query) {
    throw NotImplementedException();
}

Stream StreamApiImpl::streamGet(int64_t streamRoomId, int64_t streamId) {
    throw NotImplementedException();
}

void StreamApiImpl::streamDelete(int64_t streamId) {
    throw NotImplementedException();
}

std::string StreamApiImpl::streamTrackAdd(int64_t streamId, const StreamTrackMeta& meta) {
    throw NotImplementedException();
}

void StreamApiImpl::streamTrackRemove(const std::string& streamTrackId) {
    throw NotImplementedException();
}

List<TrackInfo> StreamApiImpl::streamTrackList(int64_t streamRoomId, int64_t streamId) {
    throw NotImplementedException();
}

void StreamApiImpl::streamTrackSendData(const std::string& streamTrackId, const core::Buffer& data) {
    throw NotImplementedException();
}

void StreamApiImpl::streamTrackRecvData(const std::string& streamTrackId, std::function<void(const core::Buffer& type)> onData) {
    throw NotImplementedException();
}

void StreamApiImpl::streamPublish(int64_t streamId) {
    throw NotImplementedException();
}

void StreamApiImpl::streamUnpublish(int64_t streamId) {
    throw NotImplementedException();
}