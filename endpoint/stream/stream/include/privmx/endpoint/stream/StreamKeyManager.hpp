/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STREAM_STREAM_KEY_MANAGER_API_HPP_
#define _PRIVMXLIB_ENDPOINT_STREAM_STREAM_KEY_MANAGER_API_HPP_

#include <string>
#include <memory>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <Poco/Dynamic/Var.h>
#include <privmx/utils/ThreadSaveMap.hpp>
#include <privmx/utils/CancellationToken.hpp>
#include <privmx/endpoint/core/KeyProvider.hpp>
#include <privmx/endpoint/core/DataEncryptorV4.hpp>
#include <privmx/endpoint/core/SubscriptionHelper.hpp>
#include <privmx/endpoint/core/SubscriptionHelper.hpp>
#include <privmx/endpoint/event/EventApiImpl.hpp>

#include "privmx/endpoint/stream/ServerTypes.hpp"
#include "privmx/endpoint/stream/ServerApi.hpp"
#include "privmx/endpoint/stream/DynamicTypes.hpp"
#include "privmx/endpoint/stream/WebRTCInterface.hpp"


namespace privmx {
namespace endpoint {
namespace stream {

class StreamKeyManager {
public:
    StreamKeyManager( 
        std::shared_ptr<event::EventApiImpl> eventApi,
        std::shared_ptr<core::KeyProvider> keyProvider, 
        std::shared_ptr<ServerApi> serverApi,
        privmx::crypto::PrivateKey userPrivKey, 
        const std::string& streamRoomId, 
        const std::string& contextId
    );
    ~StreamKeyManager();
    
    void requestKey(const std::vector<core::UserWithPubKey>& users);
    void updateKey();
    void respondToEvent(dynamic::StreamKeyManagementEvent event, const std::string& userId, const std::string& userPubKey);
    void removeUser(core::UserWithPubKey);
    int64_t addKeyUpdateCallback(std::function<void(const std::vector<privmx::endpoint::stream::Key>&)> keyUpdateCallback);
    void removeKeyUpdateCallback(int64_t keyUpdateCallbackId);
    std::vector<privmx::endpoint::stream::Key> getCurrentWebRtcKeys();
    inline void keyManagement(bool disable) {disableKeyUpdateForEncryptors=disable;}
private:
    struct StreamEncKey {
        core::EncKey key;
        std::chrono::system_clock::time_point creation_time;
        std::chrono::duration<int64_t, std::milli> TTL;
    };

    dynamic::NewStreamEncKey prepareCurrenKeyToUpdate();

    void respondToRequestKey(const std::string& userId, const std::string& userPubKey);
    void setRequestKeyResult(dynamic::RequestKeyRespondEvent result);
    void respondToUpdateRequest(dynamic::UpdateKeyEvent request, const std::string& userId, const std::string& userPubKey);
    void respondUpdateKeyConfirmation(dynamic::UpdateKeyACKEvent ack, const std::string& userPubKey);
    void sendStreamKeyManagementEvent(dynamic::StreamCustomEventData data, const std::vector<privmx::endpoint::core::UserWithPubKey>& users);
    void updateWebRtcKeyStore();

    std::shared_ptr<event::EventApiImpl> _eventApi;
    std::shared_ptr<core::KeyProvider> _keyProvider;
    std::shared_ptr<ServerApi> _serverApi;
    privmx::crypto::PrivateKey _userPrivKey;
    privmx::crypto::PublicKey _userPubKey;
    std::string _streamRoomId;
    std::string _contextId;
    core::DataEncryptorV4 _dataEncryptor;
    privmx::utils::CancellationToken::Ptr _cancellationToken;
    std::thread _keyCollector;
    std::optional<std::thread> _keyUpdater;
    privmx::utils::ThreadSaveMap<int64_t, std::function<void(const std::vector<privmx::endpoint::stream::Key>&)>> _webRtcKeyUpdateCallbacks; 

    privmx::utils::ThreadSaveMap<std::string, std::shared_ptr<StreamEncKey>> _keysStrage;
    std::vector<privmx::endpoint::core::UserWithPubKey> _connectedUsers;
    std::string _currentKeyId;
    std::shared_ptr<StreamEncKey> _keyForUpdate;
    privmx::utils::ThreadSaveMap<std::string, bool> _userUpdateKeyConfirmationStatus;
    std::mutex _updateKeyMutex;
    std::condition_variable _updateKeyCV;
    std::atomic_bool _keyUpdateInProgress = false;
    std::vector<privmx::endpoint::stream::Key> _currentWebRtcKeys;
    std::atomic_int64_t _nextKeyUpdateCallbackId = 0;
    bool disableKeyUpdateForEncryptors = false;
};

} // stream
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_STREAM_KEY_MANAGER_API_HPP_
