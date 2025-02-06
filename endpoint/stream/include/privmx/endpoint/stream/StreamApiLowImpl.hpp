/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPILOWIMPL_HPP_
#define _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPILOWIMPL_HPP_

#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <unordered_map>

#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/KeyProvider.hpp>
#include <privmx/endpoint/core/Types.hpp>
#include <privmx/endpoint/core/EventMiddleware.hpp>
#include <privmx/endpoint/core/EventChannelManager.hpp>
#include <privmx/endpoint/core/SubscriptionHelper.hpp>
#include <privmx/endpoint/core/InternalContextEventManager.hpp>
#include "privmx/endpoint/stream/Types.hpp"
#include "privmx/endpoint/stream/ServerApi.hpp"
#include "privmx/endpoint/stream/StreamRoomDataEncryptorV4.hpp"
#include "privmx/endpoint/stream/StreamKeyManager.hpp"
#include "privmx/endpoint/stream/WebRTCInterface.hpp"
namespace privmx {
namespace endpoint {
namespace stream {

class StreamApiLowImpl {
public:
    StreamApiLowImpl(
        const privfs::RpcGateway::Ptr& gateway,
        const privmx::crypto::PrivateKey& userPrivKey,
        const std::shared_ptr<core::KeyProvider>& keyProvider,
        const std::string& host,
        const std::shared_ptr<core::EventMiddleware>& eventMiddleware,
        const std::shared_ptr<core::EventChannelManager>& eventChannelManager,
        const std::shared_ptr<core::InternalContextEventManager>& internalContextEventManager
    );
    ~StreamApiLowImpl();

    std::string createStreamRoom(
        const std::string& contextId, 
        const std::vector<core::UserWithPubKey>& users, 
        const std::vector<core::UserWithPubKey>&managers,
        const core::Buffer& publicMeta, 
        const core::Buffer& privateMeta,
        const std::optional<core::ContainerPolicy>& policies
    );

    void updateStreamRoom(
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

    core::PagingList<StreamRoom> listStreamRooms(const std::string& contextId, const core::PagingQuery& query);

    StreamRoom getStreamRoom(const std::string& streamRoomId);

    void deleteStreamRoom(const std::string& streamRoomId);
    // Stream
    int64_t createStream(const std::string& streamRoomId, int64_t localStreamId, std::shared_ptr<WebRTCInterface> webRtc);
    
    // Publishing stream
    void publishStream(int64_t localStreamId);

    // Joining to Stream
    void joinStream(const std::string& streamRoomId, const std::vector<int64_t>& streamsId, const streamJoinSettings& settings, int64_t localStreamId, std::shared_ptr<WebRTCInterface> webRtc);

    std::vector<Stream> listStreams(const std::string& streamRoomId);

    std::shared_ptr<StreamKeyManager> getStreamKeyManager(const std::string& streamRoomId);

    std::shared_ptr<StreamKeyManager> getStreamKeyManager(int64_t localStreamId);

private:
    struct StreamData {
        std::shared_ptr<WebRTCInterface> webRtc;

    };
    struct StreamRoomData {
        std::map<uint64_t, std::shared_ptr<StreamData>> streamMap;
        std::shared_ptr<StreamKeyManager> streamKeyManager;
    };
    
    void processNotificationEvent(const std::string& type, const std::string& channel, const Poco::JSON::Object::Ptr& data);
    void processConnectedEvent();
    void processDisconnectedEvent();
    privmx::utils::List<std::string> mapUsers(const std::vector<core::UserWithPubKey>& users);
    DecryptedStreamRoomData decryptStreamRoomV4(const server::StreamRoomInfo& streamRoom);
    StreamRoom convertDecryptedStreamRoomDataToStreamRoom(const server::StreamRoomInfo& streamRoomInfo, const DecryptedStreamRoomData& streamRoomData);
    StreamRoom decryptAndConvertStreamRoomDataToStreamRoom(const server::StreamRoomInfo& streamRoom);
    int64_t generateNumericId();
    std::shared_ptr<StreamRoomData> createEmptyStreamRoomData(const std::string& streamRoomId);


    privfs::RpcGateway::Ptr _gateway;
    privmx::crypto::PrivateKey _userPrivKey;
    std::shared_ptr<core::KeyProvider> _keyProvider;
    std::string _host;
    std::shared_ptr<core::EventMiddleware> _eventMiddleware;
    std::shared_ptr<core::InternalContextEventManager> _internalContextEventManager;
    std::shared_ptr<ServerApi> _serverApi;
    core::SubscriptionHelper _streamSubscriptionHelper;
    StreamRoomDataEncryptorV4 _streamRoomDataEncryptorV4;
    core::DataEncryptorV4 _dataEncryptor;

    // v3 webrtc
    privmx::utils::ThreadSaveMap<std::string, std::shared_ptr<StreamRoomData>> _streamRoomMap;
    privmx::utils::ThreadSaveMap<uint64_t, std::string> _streamIdToRoomId;

    libwebrtc::scoped_refptr<libwebrtc::RTCMediaConstraints> _constraints;
    libwebrtc::RTCConfiguration _configuration;
    libwebrtc::scoped_refptr<libwebrtc::RTCAudioDevice> _audioDevice;
    libwebrtc::scoped_refptr<libwebrtc::RTCVideoDevice> _videoDevice;
    int _notificationListenerId, _connectedListenerId, _disconnectedListenerId;
};

}  // namespace stream
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPILOWIMPL_HPP_
