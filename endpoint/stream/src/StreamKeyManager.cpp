/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/stream/StreamKeyManager.hpp"


using namespace privmx::endpoint::stream; 

StreamKeyManager::StreamKeyManager(
    std::shared_ptr<privmx::webrtc::KeyProvider> webRtcKeyProvider, 
    std::shared_ptr<privmx::endpoint::core::KeyProvider> keyProvider,
    privmx::crypto::PrivateKey userPrivKey
) : _webRtcKeyProvider(webRtcKeyProvider), _keyProvider(keyProvider), _userPrivKey(userPrivKey)
{
    _userPubKey = _userPrivKey.getPublicKey();
    auto currentKey = _keyProvider->generateKey();
    _webRtcKeyProvider->setKey(currentKey.id, currentKey.key);
}
void StreamKeyManager::requestKey(const std::vector<privmx::endpoint::core::UserWithPubKey>& users) {
    // set request
}

void StreamKeyManager::respondToRequestKey(server::RequestKey request) {
    // for data encryption
    auto encKey = _keyProvider->generateKey();
    std::vector<privmx::endpoint::core::UserWithPubKey> users = { privmx::endpoint::core::UserWithPubKey{.userId=request.userId(), .pubKey=request.pubKey()} };
    auto keySet = _keyProvider->prepareKeysList(users, encKey);
    // data
    auto currentWebRtcKey = _webRtcKeyProvider->getCurrentKey();
    server::StreamEncKey currentKey = privmx::utils::TypedObjectFactory::createNewObject<server::StreamEncKey>();
    currentKey.keyId(currentWebRtcKey->keyId);
    currentKey.key(currentWebRtcKey->key);
    server::RequestKeyResult respond = privmx::utils::TypedObjectFactory::createNewObject<server::RequestKeyResult>();
    respond.encKey(currentKey);
    respond.userId(); // ?? where get userId
    respond.pubKey(_userPubKey.toBase58DER());
    // send data by event
}

void StreamKeyManager::setRequestKeyResult(server::RequestKeyResult result) {
    auto key = _dataEncryptor.de(result.EncryptedKey);
    _webRtcKeyProvider->setKey();
}

void StreamKeyManager::updateKey(const std::vector<privmx::endpoint::core::UserWithPubKey>& users) {
    auto newKey = _keyProvider->generateKey();
    auto updateKeyId = newKey.id;
    _webRtcKeyProvider->setKey(newKey.id, newKey.key);
    //
    userUpdateKeyConfirmationStatus.clear();
    for(auto user : users) {
        userUpdateKeyConfirmationStatus.set(user.userId, false);
    }
    // send to users

    //thread for timeout and update
    std::thread t([&]() {
        std::unique_lock<std::mutex> lock(updateKeyMutex);
        std::cv_status status = updateKeyCV.wait_until(lock, std::chrono::system_clock::now() + std::chrono::seconds(30));
        if (status == std::cv_status::timeout) {

        }
    }); 
}
//
void StreamKeyManager::respondToUpdateRequest(server::UpdateKey) {
    // _webRtcKeyProvider->setKey(updateKey.keyId, updateKey.key)
    // send confirmation event
}
//
void StreamKeyManager::respondUpdateKeyConfirmation(server::UpdateKeyACK) {
    // if(updateKeyId == updateKeyConfirmation.keyId) {
    //     userUpdateKeyConfirmationStatus.erase(updateKeyConfirmation.userId);
    //     if (userUpdateKeyConfirmationStatus.size() == 0) {
    //         updateKeyCV.notify_all();
    //     }
    // }
}

