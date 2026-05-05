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
#include <string>
#include <unordered_map>
#include <vector>

#include "privmx/endpoint/stream/Constants.hpp"
#include "privmx/endpoint/stream/ServerApi.hpp"
#include "privmx/endpoint/stream/SubscriberImpl.hpp"
#include "privmx/endpoint/stream/Types.hpp"
#include "privmx/endpoint/stream/WebRTCInterface.hpp"
#include "privmx/endpoint/stream/encryptors/dataChannel/DataChannelMessageEncryptorV1.hpp"
#include <privmx/utils/ManualManagedClass.hpp>
namespace privmx {
namespace endpoint {
namespace stream {

class StreamApiLowImpl : public privmx::utils::ManualManagedClass<StreamApiLowImpl>, protected core::ModuleBaseApi {
public:
    StreamApiLowImpl(
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
        const std::optional<core::ContainerPolicy>& policies,
        const std::string& type = STREAM_TYPE_FILTER_FLAG
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
    core::PagingList<StreamRoom> listStreamRooms(const std::string& contextId, const core::PagingQuery& query, const std::string& type = STREAM_TYPE_FILTER_FLAG);
    StreamRoom getStreamRoom(const std::string& streamRoomId, const std::string& type = STREAM_TYPE_FILTER_FLAG);

    void deleteStreamRoom(const std::string& streamRoomId);
    // Stream
    std::vector<StreamInfo> listStreams(const std::string& streamRoomId);
    void joinStreamRoom(const std::string& streamRoomId, std::shared_ptr<WebRTCInterface> webRtc); // required before createStream and openStream
    void leaveStreamRoom(const std::string& streamRoomId);
    void enableStreamRoomRecording(const std::string& streamRoomId);
    std::vector<stream::RecordingEncKey> getStreamRoomRecordingKeys(const std::string& streamRoomId);
    StreamHandle createStream(const std::string& streamRoomId);
    StreamPublishResult publishStream(const StreamHandle& streamHandle);
    StreamPublishResult updateStream(const StreamHandle& streamHandle);

    void unpublishStream(const StreamHandle& streamHandle);

    void subscribeToRemoteStreams(const std::string& streamRoomId, const std::vector<StreamSubscription>& subscriptions);
    void modifyRemoteStreamsSubscriptions(const std::string& streamRoomId, const std::vector<StreamSubscription>& subscriptionsToAdd, const std::vector<StreamSubscription>& subscriptionsToRemove);
    void unsubscribeFromRemoteStreams(const std::string& streamRoomId, const std::vector<StreamSubscription>& subscriptionsToRemove);

    std::vector<std::string> subscribeFor(const std::vector<std::string>& subscriptionQueries);
    void unsubscribeFrom(const std::vector<std::string>& subscriptionIds);
    std::string buildSubscriptionQuery(EventType eventType, EventSelectorType selectorType, const std::string& selectorId);

    void trickle(const int64_t sessionId, const std::string& candidateAsJson);
    void acceptOfferOnReconfigure(const int64_t sessionId, const SdpWithTypeModel& sdp);
    void setNewOfferOnReconfigure(const int64_t sessionId, const SdpWithTypeModel& sdp);

    core::Buffer encryptDataChannelMessage(const std::string& streamRoomId, const DataChannelMessage& plainMessage); 
    void registerRemoteDataChannel(const std::string& streamRoomId, const std::string& remoteStreamId);
    DecryptedDataChannelMessage decryptDataChannelMessage(const std::string& streamRoomId, const std::string& remoteStreamId, const core::Buffer& encryptedData);

    inline static const std::string STREAM_TYPE_FILTER_FLAG = "stream";
private:
    struct StreamData {
        std::optional<int64_t> sessionId;
        std::optional<StreamHandle> streamHandle;
    };
    struct StreamRoomData {
        StreamRoomData(std::shared_ptr<DataChannelMessageEncryptorV1> _messageEncryptor, const std::string _streamRoomId, std::shared_ptr<WebRTCInterface> _webRtc, const std::vector<std::string>& _subscriptionsIds, const std::string& _encryptionKeyId = ""):
            messageEncryptor(_messageEncryptor), streamRoomId(_streamRoomId), webRtc(_webRtc), subscriptionsIds(_subscriptionsIds), encryptionKeyId(_encryptionKeyId)
        {}
        std::shared_ptr<StreamData> publisherStream;
        std::shared_ptr<StreamData> subscriberStream;
        std::shared_ptr<DataChannelMessageEncryptorV1> messageEncryptor;
        std::string streamRoomId;
        std::shared_ptr<WebRTCInterface> webRtc;
        std::vector<std::string> subscriptionsIds;
        std::string encryptionKeyId;
    };
    // if streamMap is empty after leave, unpublish StreamRoomData should, be removed.

    void onNotificationEvent(const std::string& type, const core::NotificationEvent& notification);
    void processNotificationEvent(const core::NotificationEvent& notification);
    void processConnectedEvent();
    void processDisconnectedEvent();

    std::vector<std::string> mapUsers(const std::vector<core::UserWithPubKey>& users);
    StreamRoom convertServerStreamRoomToLibStreamRoom(
        server::StreamRoomInfo_c_struct streamRoomInfo,
        const core::Buffer& publicMeta = core::Buffer(),
        const core::Buffer& privateMeta = core::Buffer(),
        const int64_t& statusCode = 0,
        const int64_t& schemaVersion = StreamRoomDataSchema::Version::UNKNOWN
    );

    StreamRoom convertDecryptedStreamRoomDataV5ToStreamRoom(server::StreamRoomInfo_c_struct streamRoomInfo, const core::DecryptedModuleDataV5& streamRoomData);
    StreamRoomDataSchema::Version getStreamRoomEntryDataStructureVersion(server::StreamRoomDataEntry_c_struct streamRoomEntry);
    std::tuple<StreamRoom, core::DataIntegrityObject> decryptAndConvertStreamRoomDataToStreamRoom(server::StreamRoomInfo_c_struct streamRoom, server::StreamRoomDataEntry_c_struct streamRoomEntry, const core::DecryptedEncKey& encKey);
    std::vector<StreamRoom> decryptAndConvertStreamRoomsDataToStreamRooms(std::vector<server::StreamRoomInfo_c_struct> streamRooms);
    StreamRoom decryptAndConvertStreamRoomDataToStreamRoom(server::StreamRoomInfo_c_struct streamRoom);
    void assertStreamRoomDataIntegrity(server::StreamRoomInfo_c_struct streamRoom);
    uint32_t validateStreamRoomDataIntegrity(server::StreamRoomInfo_c_struct streamRoom);
    std::shared_ptr<StreamRoomData> createEmptyStreamRoomData(const std::string& streamRoomId, std::shared_ptr<WebRTCInterface> webRtc);

    std::shared_ptr<StreamRoomData> getStreamRoomData(const std::string& streamRoomId);
    std::shared_ptr<StreamRoomData> getStreamRoomData(const StreamHandle& streamHandle);
    std::vector<stream::Key> generateWebRTCKeysFromStreamRoomInfo(server::StreamRoomInfo_c_struct streamRoomInfo, const std::string& encryptionKeyId);
    std::unordered_map<std::string, privmx::endpoint::core::DecryptedEncKeyV2> extractStreamRoomKeys(server::StreamRoomInfo_c_struct streamRoomInfo);
    std::string deriveStreamEncryptionKey(privmx::endpoint::core::DecryptedEncKeyV2 EncKey);

    virtual std::pair<core::ModuleKeys, int64_t> getModuleKeysAndVersionFromServer(std::string moduleId) override;
    core::ModuleKeys streamRoomToModuleKeys(server::StreamRoomInfo_c_struct streamRoom);
    void assertTurnServerUri(const std::string& uri);

    static int32_t nextIdCounter;
    static int32_t nextId() {
        return nextIdCounter++;
    }


    std::shared_ptr<core::ConnectionImpl> _connection;
    privmx::crypto::PrivateKey _userPrivKey;
    std::shared_ptr<core::KeyProvider> _keyProvider;
    std::string _host;
    std::shared_ptr<core::EventMiddleware> _eventMiddleware;
    std::shared_ptr<ServerApi> _serverApi;
    stream::SubscriberImpl _subscriber;
    core::ModuleDataEncryptorV5 _streamRoomDataEncryptorV5;

    // v3 webrtc
    privmx::utils::ThreadSaveMap<std::string, std::shared_ptr<StreamRoomData>> _streamRoomMap;
    privmx::utils::ThreadSaveMap<StreamHandle, std::string> _streamHandleToRoomId;
    int _notificationListenerId, _connectedListenerId, _disconnectedListenerId;
};

}  // namespace stream
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPILOWIMPL_HPP_
