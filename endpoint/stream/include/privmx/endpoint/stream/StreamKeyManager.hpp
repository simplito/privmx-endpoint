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
#include <pmx_frame_cryptor.h>
#include <privmx/utils/ThreadSaveMap.hpp>
#include <privmx/endpoint/core/KeyProvider.hpp>
#include <privmx/endpoint/core/DataEncryptorV4.hpp>
#include "privmx/endpoint/stream/ServerTypes.hpp"
#include "privmx/endpoint/stream/ServerApi.hpp"

namespace privmx {
namespace endpoint {
namespace stream {

class StreamKeyManager {
public:
    StreamKeyManager(
        std::shared_ptr<privmx::webrtc::KeyProvider> webRtcKeyProvider, 
        std::shared_ptr<core::KeyProvider> keyProvider, 
        std::shared_ptr<ServerApi> serverApi,
        privmx::crypto::PrivateKey userPrivKey, 
        const std::string& streamRoomId
    );
    
    void requestKey(const std::vector<core::UserWithPubKey>& users);
    void updateKey(const std::vector<core::UserWithPubKey>& users);
    void respondToEvent(server::StreamKeyManagementEvent event, const std::string& userId, const std::string& userPubKey);
    
private:
    struct StreamEncKey {
        core::EncKey key;
        std::chrono::_V2::system_clock::time_point creation_time;
        std::chrono::duration<int64_t, std::milli> TTL;
    };

    server::NewStreamEncKey prepareCurrenKeyToUpdate();

    void respondToRequestKey(server::RequestKeyEvent request, const std::string& userId, const std::string& userPubKey);
    void setRequestKeyResult(server::RequestKeyRespondEvent result);
    void respondToUpdateRequest(server::UpdateKeyEvent request, const std::string& userId, const std::string& userPubKey);
    void respondUpdateKeyConfirmation(server::UpdateKeyACKEvent ack, const std::string& userId, const std::string& userPubKey);

    void sendStreamKeyManagementEvent(server::StreamCustomEventData data, const std::vector<privmx::endpoint::core::UserWithPubKey>& users);
    privmx::utils::List<core::server::UserKey> createKeySet(const std::vector<core::UserWithPubKey>& users, const privmx::endpoint::core::EncKey& key);

    std::shared_ptr<privmx::webrtc::KeyProvider> _webRtcKeyProvider;
    std::shared_ptr<core::KeyProvider> _keyProvider;
    std::shared_ptr<ServerApi> _serverApi;
    privmx::crypto::PrivateKey _userPrivKey;
    privmx::crypto::PublicKey _userPubKey;
    std::string _streamRoomId;
    std::string _contextId;
    core::DataEncryptorV4 _dataEncryptor;

    std::unordered_map<std::string, std::shared_ptr<StreamEncKey>> _keysStrage;
    std::string _currentKeyId;
    std::shared_ptr<StreamEncKey> _keyForUpdate;
    privmx::utils::ThreadSaveMap<std::string, bool> _userUpdateKeyConfirmationStatus;
    std::mutex _updateKeyMutex;
    std::condition_variable _updateKeyCV;
    

};

} // stream
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_STREAM_KEY_MANAGER_API_HPP_
