/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPIIMPL_HPP_
#define _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPIIMPL_HPP_

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/KeyProvider.hpp>
#include <privmx/endpoint/core/Types.hpp>
#include <privmx/endpoint/core/EventMiddleware.hpp>
#include <privmx/endpoint/core/EventChannelManager.hpp>
#include <privmx/endpoint/core/SubscriptionHelper.hpp>
#include "privmx/endpoint/stream/Types.hpp"
#include "privmx/endpoint/stream/ServerApi.hpp"
#include "privmx/endpoint/stream/StreamRoomDataEncryptorV4.hpp"


namespace privmx {
namespace endpoint {
namespace stream {

class StreamApiImpl {
public:
    StreamApiImpl(
        const privfs::RpcGateway::Ptr& gateway,
        const privmx::crypto::PrivateKey& userPrivKey,
        const std::shared_ptr<core::KeyProvider>& keyProvider,
        const std::string& host,
        const std::shared_ptr<core::EventMiddleware>& eventMiddleware,
        const std::shared_ptr<core::EventChannelManager>& eventChannelManager,
        const core::Connection& connection
    );
    ~StreamApiImpl();

    std::string roomCreate(
        const std::string& contextId, 
        const std::vector<core::UserWithPubKey>& users, 
        const std::vector<core::UserWithPubKey>&managers,
        const core::Buffer& publicMeta, 
        const core::Buffer& privateMeta,
        const std::optional<core::ContainerPolicy>& policies
    );

    void roomUpdate(
        const std::string& streamRoomId, 
        const std::vector<core::UserWithPubKey>& users, 
        const std::vector<core::UserWithPubKey>&managers,
        const core::Buffer& publicMeta, 
        const core::Buffer& privateMeta, 
        const int64_t version, 
        const bool force, 
        const bool forceGenerateNewKey, 
        const std::optional<core::ContainerPolicy>& policies
    );

    core::PagingList<StreamRoom> streamRoomList(const std::string& contextId, const core::PagingQuery& query);

    StreamRoom streamRoomGet(const std::string& streamRoomId);

    void streamRoomDelete(const std::string& streamRoomId);
    // streamCreate
    int64_t streamCreate(const std::string& streamRoomId, const StreamCreateMeta& meta);

    void streamUpdate(int64_t streamId, const StreamCreateMeta& meta);

    core::PagingList<Stream> streamList(const std::string& streamRoomId, const core::PagingQuery& query);

    Stream streamGet(const std::string& streamRoomId, int64_t streamId);

    void streamDelete(int64_t streamId);

    // // streamTrackAdd
    std::string streamTrackAdd(int64_t streamId, const StreamTrackMeta& meta);
    void streamTrackRemove(const std::string& streamTrackId);
    List<TrackInfo> streamTrackList(const std::string& streamRoomId, int64_t streamId);

    // funkcje specyficzne dla data-channeli
    // streamTrackSendData (odpowiednik dataChannel - zapisac w dokumentacji)
    void streamTrackSendData(const std::string& streamTrackId, const core::Buffer& data);
    // funkcja powinna byc blokujaca - zeby nie bylo callbackow / wewnetrznie moze byc dowolnie
    // streamTrackRecvData
    void streamTrackRecvData(const std::string& streamTrackId, std::function<void(const core::Buffer& type)> onData);

    // streamPublish
    void streamPublish(int64_t streamId);

    // // streamUnpublish
    void streamUnpublish(int64_t streamId);

    void streamJoin(const std::string& streamRoomId, const StreamAndTracksSelector& streamToJoin);
    void streamLeave(int64_t streamId);

    // ... tymczasowy callback na nowo pojawiajace sie zdalne kanały (które chcielibysmy czytać)
    // to zostanie ostatecznie zmergowane do waitEvent
    // void testAddRemoteStreamListener(RemoteStreamListener listener);
    // void testSetStreamEncKey(core::EncKey key);
    
private:
    privmx::utils::List<std::string> mapUsers(const std::vector<core::UserWithPubKey>& users);
    DecryptedStreamRoomData decryptStreamRoomV4(const server::StreamRoomInfo& streamRoom);
    StreamRoom convertDecryptedStreamRoomDataToStreamRoom(const server::StreamRoomInfo& streamRoomInfo, const DecryptedStreamRoomData& streamRoomData);
    StreamRoom decryptAndConvertStreamRoomDataToStreamRoom(const server::StreamRoomInfo& streamRoom);

    privfs::RpcGateway::Ptr _gateway;
    privmx::crypto::PrivateKey _userPrivKey;
    std::shared_ptr<core::KeyProvider> _keyProvider;
    std::string _host;
    std::shared_ptr<core::EventMiddleware> _eventMiddleware;
    core::Connection _connection;
    ServerApi _serverApi;


    StreamRoomDataEncryptorV4 _streamRoomDataEncryptorV4;
};

}  // namespace stream
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPIIMPL_HPP_
