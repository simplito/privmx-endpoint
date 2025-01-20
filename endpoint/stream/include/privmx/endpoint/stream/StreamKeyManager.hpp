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

namespace privmx {
namespace endpoint {
namespace stream {

class StreamKeyManager {
public:
    StreamKeyManager(std::shared_ptr<privmx::webrtc::KeyProvider> webRtcKeyProvider, std::shared_ptr<core::KeyProvider> keyProvider, privmx::crypto::PrivateKey userPrivKey);
    
    void requestKey(const std::vector<core::UserWithPubKey>& users);
    void respondToRequestKey(server::RequestKey request);
    void setRequestKeyResult(server::RequestKeyResult result);
    void updateKey(const std::vector<core::UserWithPubKey>& users);
    void respondToUpdateRequest(server::UpdateKey request);
    void respondUpdateKeyConfirmation(server::UpdateKeyACK ack);
    
private:
    
    std::shared_ptr<privmx::webrtc::KeyProvider> _webRtcKeyProvider;
    std::shared_ptr<core::KeyProvider> _keyProvider;
    privmx::crypto::PrivateKey _userPrivKey;
    privmx::crypto::PublicKey _userPubKey;
    std::string _userId;
    core::DataEncryptorV4 _dataEncryptor;

    std::string updateKeyId;
    privmx::utils::ThreadSaveMap<std::string, bool> userUpdateKeyConfirmationStatus;
    std::mutex updateKeyMutex;
    std::condition_variable updateKeyCV;
    

};

} // stream
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_STREAM_KEY_MANAGER_API_HPP_
