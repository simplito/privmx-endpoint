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
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/EventMiddleware.hpp>
#include <privmx/endpoint/core/KeyProvider.hpp>
#include <privmx/endpoint/core/ModuleBaseApi.hpp>
#include <privmx/endpoint/core/Types.hpp>
#include <privmx/endpoint/core/encryptors/module/ModuleDataEncryptorV5.hpp>
#include <privmx/endpoint/event/EventApiImpl.hpp>
#include <string>
#include <unordered_map>
#include <vector>

#include "privmx/endpoint/stream/Constants.hpp"
#include "privmx/endpoint/stream/ServerApi.hpp"
#include "privmx/endpoint/stream/StreamKeyManager.hpp"
#include "privmx/endpoint/stream/SubscriberImpl.hpp"
#include "privmx/endpoint/stream/Types.hpp"
#include "privmx/endpoint/stream/WebRTCInterface.hpp"
namespace privmx {
namespace endpoint {
namespace stream {

class StreamApiLowImpl : protected core::ModuleBaseApi {
public:
    StreamApiLowImpl(
        const std::shared_ptr<event::EventApiImpl>& eventApi,
        const core::Connection& connection,
        const privfs::RpcGateway::Ptr& gateway,
        const privmx::crypto::PrivateKey& userPrivKey,
        const std::shared_ptr<core::KeyProvider>& keyProvider,
        const std::string& host,
        const std::shared_ptr<core::EventMiddleware>& eventMiddleware
    );
    ~StreamApiLowImpl();

    std::vector<TurnCredentials> getTurnCredentials();

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
    int64_t joinStream(const std::string& streamRoomId, const std::vector<int64_t>& streamsId, const Settings& settings, int64_t localStreamId, std::shared_ptr<WebRTCInterface> webRtc);

    std::vector<Stream> listStreams(const std::string& streamRoomId);

    void unpublishStream(int64_t localStreamId);

    void leaveStream(const std::string& streamRoomId, const std::vector<int64_t>& streamsIds);

    std::vector<std::string> subscribeFor(const std::vector<std::string>& subscriptionQueries);
    void unsubscribeFrom(const std::vector<std::string>& subscriptionIds);
    std::string buildSubscriptionQuery(EventType eventType, EventSelectorType selectorType, const std::string& selectorId);

    void keyManagement(bool disable);

    void reconfigureStream(int64_t localStreamId, const std::string& optionsJSON = "{}");

    void trickle(const int64_t sessionId, const dynamic::RTCIceCandidate& candidate);

    void acceptOfferOnReconfigure(const int64_t sessionId, const SdpWithTypeModel& sdp);
private:
    struct StreamData {
        std::shared_ptr<WebRTCInterface> webRtc;
        std::optional<int64_t> sessionId;
        int64_t updateId;
    };
    struct StreamRoomData {
        StreamRoomData(std::shared_ptr<StreamKeyManager> _streamKeyManager, const std::string _id, std::shared_ptr<WebRTCInterface> _webRtc):
            streamMap(privmx::utils::ThreadSaveMap<int64_t, std::shared_ptr<StreamData>>()), 
            streamKeyManager(_streamKeyManager), id(_id), webRtc(_webRtc) {}
        
        privmx::utils::ThreadSaveMap<int64_t, std::shared_ptr<StreamData>> streamMap;
        std::shared_ptr<StreamKeyManager> streamKeyManager;
        std::string id;
        std::shared_ptr<WebRTCInterface> webRtc;
    }; 
    // if streamMap is empty after leave, unpublish StreamRoomData should, be removed.
    
    void processNotificationEvent(const std::string& type, const core::NotificationEvent& notification);
    void processConnectedEvent();
    void processDisconnectedEvent();

    // bool isInternalJanusEvent(const std::string& type, const Poco::JSON::Object::Ptr data);
    // void processJanusEvent(const Poco::JSON::Object::Ptr data);
    // void onVideoRoomUpdate(const int64_t session_id, server::JanusVideoRoomUpdated updateEvent, std::shared_ptr<StreamData> streamData, const std::optional<server::JanusJSEP>& jsep = std::nullopt);

    privmx::utils::List<std::string> mapUsers(const std::vector<core::UserWithPubKey>& users);
    StreamRoom convertServerStreamRoomToLibStreamRoom(
        server::StreamRoomInfo streamRoomInfo,
        const core::Buffer& publicMeta = core::Buffer(),
        const core::Buffer& privateMeta = core::Buffer(),
        const int64_t& statusCode = 0,
        const int64_t& schemaVersion = StreamRoomDataSchema::Version::UNKNOWN
    );
    StreamRoom convertDecryptedStreamRoomDataV5ToStreamRoom(server::StreamRoomInfo streamRoomInfo, const core::DecryptedModuleDataV5& streamRoomData);
    StreamRoomDataSchema::Version getStreamRoomEntryDataStructureVersion(server::StreamRoomDataEntry streamRoomEntry);
    std::tuple<StreamRoom, core::DataIntegrityObject> decryptAndConvertStreamRoomDataToStreamRoom(server::StreamRoomInfo streamRoom, server::StreamRoomDataEntry streamRoomEntry, const core::DecryptedEncKey& encKey);
    std::vector<StreamRoom> decryptAndConvertStreamRoomsDataToStreamRooms(utils::List<server::StreamRoomInfo> streamRooms);
    StreamRoom decryptAndConvertStreamRoomDataToStreamRoom(server::StreamRoomInfo streamRoom);
    void assertStreamRoomDataIntegrity(server::StreamRoomInfo streamRoom);
    uint32_t validateStreamRoomDataIntegrity(server::StreamRoomInfo streamRoom);
    int64_t generateNumericId();
    std::shared_ptr<StreamRoomData> createEmptyStreamRoomData(const std::string& streamRoomId, std::shared_ptr<WebRTCInterface> webRtc);

    std::shared_ptr<StreamRoomData> getStreamRoomData(const std::string& streamRoomId);
    std::shared_ptr<StreamRoomData> getStreamRoomData(int64_t localStreamId);
    std::shared_ptr<StreamData> getStreamData(int64_t localStreamId, std::shared_ptr<StreamRoomData> room);

    void removeStream(std::shared_ptr<StreamRoomData> room, std::shared_ptr<StreamData> streamData, int64_t localStreamId);

    virtual std::pair<core::ModuleKeys, int64_t> getModuleKeysAndVersionFromServer(std::string moduleId) override;
    core::ModuleKeys streamRoomToModuleKeys(server::StreamRoomInfo streamRoom);

    std::shared_ptr<event::EventApiImpl> _eventApi;
    std::shared_ptr<core::ConnectionImpl> _connection;
    privfs::RpcGateway::Ptr _gateway;
    privmx::crypto::PrivateKey _userPrivKey;
    std::shared_ptr<core::KeyProvider> _keyProvider;
    std::string _host;
    std::shared_ptr<core::EventMiddleware> _eventMiddleware;
    std::shared_ptr<ServerApi> _serverApi;
    stream::SubscriberImpl _subscriber;
    core::ModuleDataEncryptorV5 _streamRoomDataEncryptorV5;
    core::DataEncryptorV4 _dataEncryptor;

    // v3 webrtc
    privmx::utils::ThreadSaveMap<std::string, std::shared_ptr<StreamRoomData>> _streamRoomMap;
    privmx::utils::ThreadSaveMap<int64_t, std::string> _streamIdToRoomId;
    privmx::utils::ThreadSaveMap<int64_t, int64_t> _sessionIdToStreamId;
    int _notificationListenerId, _connectedListenerId, _disconnectedListenerId;
    std::vector<std::string> _internalSubscriptionIds;
};

}  // namespace stream
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPILOWIMPL_HPP_
