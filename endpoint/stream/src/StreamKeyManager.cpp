/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/stream/StreamKeyManager.hpp"

#define MAX_UPDATE_TIMEOUT 1000*30
#define MAX_STD_KEY_TTL 1000*60*5

using namespace privmx::endpoint::stream; 

StreamKeyManager::StreamKeyManager(
    std::shared_ptr<privmx::webrtc::KeyProvider> webRtcKeyProvider, 
    std::shared_ptr<core::KeyProvider> keyProvider, 
    std::shared_ptr<ServerApi> serverApi,
    privmx::crypto::PrivateKey userPrivKey, 
    const std::string& streamRoomId
) : _webRtcKeyProvider(webRtcKeyProvider), _keyProvider(keyProvider), _serverApi(serverApi), _userPrivKey(userPrivKey), _streamRoomId(streamRoomId) {
    _userPubKey = _userPrivKey.getPublicKey();
    // generate curren key
    auto currentKey = _keyProvider->generateKey();
    _keyForUpdate = std::make_shared<StreamEncKey>(StreamEncKey{
        .key=currentKey, 
        .creation_time=std::chrono::system_clock::now(), 
        .TTL=std::chrono::milliseconds(MAX_STD_KEY_TTL)
    });
    _webRtcKeyProvider->setKey(currentKey.id, currentKey.key);
    //create thread to remove old keys
}

void StreamKeyManager::respondToEvent(server::StreamKeyManagementEvent event, const std::string& userId, const std::string& userPubKey) {
    if(event.subtype() == "RequestKeyEvent") {
        respondToRequestKey(privmx::utils::TypedObjectFactory::createObjectFromVar<server::RequestKeyEvent>(event), userId, userPubKey);
    } else if(event.subtype() == "RequestKeyRespondEvent") {
        setRequestKeyResult(privmx::utils::TypedObjectFactory::createObjectFromVar<server::RequestKeyRespondEvent>(event));
    } else if(event.subtype() == "UpdateKeyEvent") {
        respondToUpdateRequest(privmx::utils::TypedObjectFactory::createObjectFromVar<server::UpdateKeyEvent>(event), userId, userPubKey);
    } else if(event.subtype() == "UpdateKeyACKEvent") {
        respondUpdateKeyConfirmation(privmx::utils::TypedObjectFactory::createObjectFromVar<server::UpdateKeyACKEvent>(event), userId, userPubKey);
    }
}

void StreamKeyManager::requestKey(const std::vector<privmx::endpoint::core::UserWithPubKey>& users) {
    // prepare data to send
    server::RequestKeyEvent request = privmx::utils::TypedObjectFactory::createNewObject<server::RequestKeyEvent>();
    request.subtype("RequestKeyEvent");
    // send to users
    sendStreamKeyManagementEvent(request, users);
}

void StreamKeyManager::respondToRequestKey(server::RequestKeyEvent request, const std::string& userId, const std::string& userPubKey) {
    // data
    auto currentKey = _keysStrage.at(_currentKeyId);

    server::StreamEncKey streamEncKey = privmx::utils::TypedObjectFactory::createNewObject<server::StreamEncKey>();
    streamEncKey.keyId(currentKey->key.id);
    streamEncKey.key(currentKey->key.key);
    auto ttl = currentKey->creation_time + currentKey->TTL - std::chrono::system_clock::now();
    std::chrono::milliseconds ttlMilli = std::chrono::duration_cast<std::chrono::milliseconds>(ttl);
    streamEncKey.TTL(ttlMilli.count());
    server::RequestKeyRespondEvent respond = privmx::utils::TypedObjectFactory::createNewObject<server::RequestKeyRespondEvent>();
    respond.subtype("RequestKeyEvent");
    respond.encKey(streamEncKey);
    // send data by event
    sendStreamKeyManagementEvent(respond, {privmx::endpoint::core::UserWithPubKey{.userId=userId, .pubKey=userPubKey}});
}

void StreamKeyManager::setRequestKeyResult(server::RequestKeyRespondEvent result) {
    //validate data
    auto newKey = result.encKey();
    // add new key
    _keysStrage.insert(
        std::make_pair(
            newKey.keyId(),
            std::make_shared<StreamEncKey>(
                StreamEncKey{
                    .key=privmx::endpoint::core::EncKey{.id=newKey.keyId(), .key=newKey.key()},
                    .creation_time=std::chrono::system_clock::now(), 
                    .TTL=std::chrono::milliseconds(newKey.TTL())
                }
            )
        )
    );
    _webRtcKeyProvider->setKey(newKey.keyId(), newKey.key());
}

void StreamKeyManager::updateKey(const std::vector<privmx::endpoint::core::UserWithPubKey>& users) {
    // create date
    auto newKey = prepareCurrenKeyToUpdate();
    _userUpdateKeyConfirmationStatus.clear();
    for(auto user : users) {
        _userUpdateKeyConfirmationStatus.set(user.pubKey, false);
    }
    // prepare data to send
    server::UpdateKeyEvent respond = privmx::utils::TypedObjectFactory::createNewObject<server::UpdateKeyEvent>();
    respond.subtype("UpdateKeyEvent");
    respond.encKey(newKey);
    // send to users
    sendStreamKeyManagementEvent(respond, users);
    //thread for timeout and update
    std::thread t([&]() {
        std::unique_lock<std::mutex> lock(_updateKeyMutex);
        std::cv_status status = _updateKeyCV.wait_until(lock, std::chrono::system_clock::now() + std::chrono::milliseconds(MAX_UPDATE_TIMEOUT));
        if (status == std::cv_status::timeout) {

        }
    }); 
}
//
void StreamKeyManager::respondToUpdateRequest(server::UpdateKeyEvent request, const std::string& userId, const std::string& userPubKey) {
    //extract key
    auto newKey = request.encKey();
    // add new key
    _keysStrage.insert(
        std::make_pair(
            newKey.keyId(),
            std::make_shared<StreamEncKey>(
                StreamEncKey{
                    .key=privmx::endpoint::core::EncKey{.id=newKey.keyId(), .key=newKey.key()},
                    .creation_time=std::chrono::system_clock::now(), 
                    .TTL=std::chrono::milliseconds(newKey.TTL())
                }
            )
        )
    );
    _webRtcKeyProvider->setKey(newKey.keyId(), newKey.key());
    // prepare ack data
    server::UpdateKeyACKEvent ack = privmx::utils::TypedObjectFactory::createNewObject<server::UpdateKeyACKEvent>();
    ack.subtype("UpdateKeyACKEvent");
    ack.keyId(newKey.keyId());
    // send confirmation event
    sendStreamKeyManagementEvent(ack, {privmx::endpoint::core::UserWithPubKey{.userId=userId, .pubKey=userPubKey}});
}

void StreamKeyManager::respondUpdateKeyConfirmation(server::UpdateKeyACKEvent ack, const std::string& userId, const std::string& userPubKey) {
    if(_keyForUpdate->key.id == ack.keyId()) {
        _userUpdateKeyConfirmationStatus.erase(userPubKey);
        if (_userUpdateKeyConfirmationStatus.size() == 0) {
            _updateKeyCV.notify_all();
        }
    }
}

server::NewStreamEncKey StreamKeyManager::prepareCurrenKeyToUpdate() {
    _keyForUpdate = std::make_shared<StreamEncKey>(StreamEncKey{
        .key=_keyProvider->generateKey(), 
        .creation_time=std::chrono::system_clock::now(), 
        .TTL=std::chrono::milliseconds(MAX_STD_KEY_TTL)
    });
    auto currentKey = _keysStrage.at(_currentKeyId);
    server::NewStreamEncKey result = privmx::utils::TypedObjectFactory::createNewObject<server::NewStreamEncKey>();
    result.oldKeyId(currentKey->key.id);
    
    if( currentKey->creation_time + currentKey->TTL >= std::chrono::system_clock::now() - std::chrono::milliseconds(MAX_UPDATE_TIMEOUT)) {
        result.oldKeyTTL(std::chrono::milliseconds(MAX_UPDATE_TIMEOUT).count());

    } else {
        auto ttl = currentKey->creation_time + currentKey->TTL - std::chrono::system_clock::now();
        std::chrono::milliseconds ttlMilli = std::chrono::duration_cast<std::chrono::milliseconds>(ttl);
        result.oldKeyTTL(ttlMilli.count());
    }
    result.key(_keyForUpdate->key.key);
    result.keyId(_keyForUpdate->key.id);
    auto ttl = _keyForUpdate->creation_time + _keyForUpdate->TTL - std::chrono::system_clock::now();
    std::chrono::milliseconds ttlMilli = std::chrono::duration_cast<std::chrono::milliseconds>(ttl);
    result.TTL(ttlMilli.count());
    return result;
}

void StreamKeyManager::sendStreamKeyManagementEvent(server::StreamCustomEventData data, const std::vector<privmx::endpoint::core::UserWithPubKey>& users) {
    data.type("StreamKeyManagementEvent");
    data.streamRoomId(_streamRoomId);
    auto key = _keyProvider->generateKey();
    std::string encryptedData = _dataEncryptor.signAndEncryptAndEncode(privmx::endpoint::core::Buffer::from(privmx::utils::Utils::stringifyVar(data)), _userPrivKey, key.key);
    core::server::CustomEventModel model = privmx::utils::TypedObjectFactory::createNewObject<core::server::CustomEventModel>();
    model.contextId(_contextId);
    model.keyId();
    model.eventData(encryptedData);
    model.users(createKeySet(users, key));
    _serverApi->streamCustomEvent(model);
}

privmx::utils::List<privmx::endpoint::core::server::UserKey> StreamKeyManager::createKeySet(const std::vector<privmx::endpoint::core::UserWithPubKey>& users, const privmx::endpoint::core::EncKey& key) {
    auto usersKeySet = _keyProvider->prepareKeysList(users, key);
    auto result = privmx::utils::TypedObjectFactory::createNewList<privmx::endpoint::core::server::UserKey>();
    for (auto userKey : usersKeySet) {
        auto el = privmx::utils::TypedObjectFactory::createNewObject<privmx::endpoint::core::server::UserKey>();
        el.id(userKey.user());
        el.key(userKey.data());
        result.add(el);
    }
    return result;
}