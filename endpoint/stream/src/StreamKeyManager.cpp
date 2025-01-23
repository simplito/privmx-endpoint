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
    std::shared_ptr<core::KeyProvider> keyProvider, 
    std::shared_ptr<ServerApi> serverApi,
    privmx::crypto::PrivateKey userPrivKey, 
    const std::string& streamRoomId,
    const std::string& contextId
) : _keyProvider(keyProvider), _serverApi(serverApi), _userPrivKey(userPrivKey), _streamRoomId(streamRoomId), _contextId(contextId) {
    _userPubKey = _userPrivKey.getPublicKey();
    // generate curren key
    auto currentKey = _keyProvider->generateKey();
    _keyForUpdate = std::make_shared<StreamEncKey>(StreamEncKey{
        .key=currentKey, 
        .creation_time=std::chrono::system_clock::now(), 
        .TTL=std::chrono::milliseconds(MAX_STD_KEY_TTL)
    });
    _keysStrage.set(_keyForUpdate->key.id, _keyForUpdate);
    updateWebRtcKeyStore();
    // ->setKey(currentKey.id, currentKey.key);
    _cancellationToken = privmx::utils::CancellationToken::create();
    //create thread to remove old keys
    _keyCollector = std::thread([&]() {
        while (true) {
            _cancellationToken->sleep(std::chrono::seconds(1));
            std::vector<std::string> keysToDelete;
            _keysStrage.forAll([&](std::string key, std::shared_ptr<StreamEncKey> value) {
                if(value->creation_time + value->TTL > std::chrono::system_clock::now()) {
                    keysToDelete.push_back(key);
                }
            });
            for(auto keyToDelete: keysToDelete) {
                _keysStrage.erase(keyToDelete);
            }
            if(keysToDelete.size() > 0) {
                updateWebRtcKeyStore();
            }
        }
    }); 
    _keyCollector.detach();
}

StreamKeyManager::~StreamKeyManager() {
    _cancellationToken->cancel();
}
#include <iostream>
std::shared_ptr<privmx::webrtc::KeyStore> StreamKeyManager::getCurrentWebRtcKeyStore() {
    _keysStrage.forAll([&](std::string key, std::shared_ptr<StreamEncKey> value) {
        std::cout << key << std::endl; 
        auto tmp = _currentWebRtcKeyStore->getKey(key);
        std::cout << tmp->keyId << " " << tmp->key << "" << tmp->type << std::endl; 
    });
    return _currentWebRtcKeyStore;
}

int64_t StreamKeyManager::addFrameCryptor(std::shared_ptr<privmx::webrtc::FrameCryptor> frameCryptor) {
    int64_t id = ++_nextFrameCryptorId;
    _webRtcFrameCryptors.set(id, frameCryptor);
    frameCryptor->setKeyStore(_currentWebRtcKeyStore);
    return id;
}

void StreamKeyManager::removeFrameCryptor(int64_t frameCryptorId) {
    _webRtcFrameCryptors.erase(frameCryptorId);
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
    auto currentKey = _keyForUpdate;

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
    _connectedUsers.push_back(privmx::endpoint::core::UserWithPubKey{.userId=userId, .pubKey=userPubKey});
}

void StreamKeyManager::setRequestKeyResult(server::RequestKeyRespondEvent result) {
    //validate data
    auto newKey = result.encKey();
    // add new key
    _keysStrage.set(
        newKey.keyId(),
        std::make_shared<StreamEncKey>(
            StreamEncKey{
                .key=privmx::endpoint::core::EncKey{.id=newKey.keyId(), .key=newKey.key()},
                .creation_time=std::chrono::system_clock::now(), 
                .TTL=std::chrono::milliseconds(newKey.TTL())
            }
        )
    );
    updateWebRtcKeyStore();
}

void StreamKeyManager::removeUser(core::UserWithPubKey user) {
    _connectedUsers.erase(
        std::find_if(
            _connectedUsers.begin(), 
            _connectedUsers.end(), 
            [user](const core::UserWithPubKey& u) {return user.userId == u.userId && user.pubKey == u.pubKey;}
        )
    );
}

void StreamKeyManager::updateKey() {
    // create date
    auto newKey = prepareCurrenKeyToUpdate();
    _userUpdateKeyConfirmationStatus.clear();
    for(auto user : _connectedUsers) {
        _userUpdateKeyConfirmationStatus.set(user.pubKey, false);
    }
    // prepare data to send
    server::UpdateKeyEvent respond = privmx::utils::TypedObjectFactory::createNewObject<server::UpdateKeyEvent>();
    respond.subtype("UpdateKeyEvent");
    respond.encKey(newKey);
    // send to users
    sendStreamKeyManagementEvent(respond, _connectedUsers);
    //thread for timeout and update
    std::thread t([&]() {
        std::unique_lock<std::mutex> lock(_updateKeyMutex);
        std::cv_status status = _updateKeyCV.wait_until(lock, std::chrono::system_clock::now() + std::chrono::milliseconds(MAX_UPDATE_TIMEOUT));
        _keysStrage.set(_keyForUpdate->key.id, _keyForUpdate);
        _keysStrage.erase(_currentKeyId);
        _currentKeyId = _keyForUpdate->key.id;
    }); 
    t.detach();
}
//
void StreamKeyManager::respondToUpdateRequest(server::UpdateKeyEvent request, const std::string& userId, const std::string& userPubKey) {
    //extract key
    auto newKey = request.encKey();
    // add new key
    _keysStrage.set(
        newKey.keyId(),
        std::make_shared<StreamEncKey>(
            StreamEncKey{
                .key=privmx::endpoint::core::EncKey{.id=newKey.keyId(), .key=newKey.key()},
                .creation_time=std::chrono::system_clock::now(), 
                .TTL=std::chrono::milliseconds(newKey.TTL())
            }
        )
    );
    updateWebRtcKeyStore();
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
    {
        std::unique_lock<std::mutex> lock(_updateKeyMutex);
        _keyForUpdate = std::make_shared<StreamEncKey>(StreamEncKey{
            .key=_keyProvider->generateKey(), 
            .creation_time=std::chrono::system_clock::now(), 
            .TTL=std::chrono::milliseconds(MAX_STD_KEY_TTL)
        });
    }

    auto currentKeyOpt = _keysStrage.get(_currentKeyId);
    auto currentKey = currentKeyOpt.value();
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
    model.data(encryptedData);
    model.channel("internal");
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

void StreamKeyManager::updateWebRtcKeyStore() {
    std::vector<privmx::webrtc::Key> webRtcKeys;
    _keysStrage.forAll([&](std::string key, std::shared_ptr<StreamEncKey> value) {
        privmx::webrtc::Key webRtcKey {
            .keyId = value->key.id,
            .key =  value->key.key,
            .type = value->key.id == _currentKeyId ? privmx::webrtc::KeyType::LOCAL : privmx::webrtc::KeyType::REMOTE
        };
        webRtcKeys.push_back(webRtcKey);
    });
    _currentWebRtcKeyStore = privmx::webrtc::KeyStore::Create(webRtcKeys);
    _webRtcFrameCryptors.forAll([&](int64_t key, std::shared_ptr<privmx::webrtc::FrameCryptor> value) {
        value->setKeyStore(_currentWebRtcKeyStore);
    });
}
