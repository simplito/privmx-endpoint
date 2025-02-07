/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/stream/StreamKeyManager.hpp"
#include <iostream>
#include <privmx/utils/Debug.hpp>

#define MAX_UPDATE_TIMEOUT 1000*5
#define MAX_STD_KEY_TTL 1000*60

using namespace privmx::endpoint::stream; 

StreamKeyManager::StreamKeyManager(
    std::shared_ptr<core::KeyProvider> keyProvider, 
    std::shared_ptr<ServerApi> serverApi,
    privmx::crypto::PrivateKey userPrivKey, 
    const std::string& streamRoomId,
    const std::string& contextId,
    const std::shared_ptr<core::InternalContextEventManager>& internalContextEventManager
) : _keyProvider(keyProvider), _serverApi(serverApi), _userPrivKey(userPrivKey), _streamRoomId(streamRoomId), _contextId(contextId), _internalContextEventManager(internalContextEventManager) {
    _userPubKey = _userPrivKey.getPublicKey();
    // generate curren key
    auto currentKey = _keyProvider->generateKey();
    _keyForUpdate = std::make_shared<StreamEncKey>(StreamEncKey{
        .key=currentKey, 
        .creation_time=std::chrono::system_clock::now(), 
        .TTL=std::chrono::milliseconds(MAX_STD_KEY_TTL)
    });
    _keysStrage.set(_keyForUpdate->key.id, _keyForUpdate);
    _currentKeyId = _keyForUpdate->key.id;
    updateWebRtcKeyStore();
    // ->setKey(currentKey.id, currentKey.key);
    _cancellationToken = privmx::utils::CancellationToken::create();
    //create thread to remove old keys
    _keyCollector = std::thread([&]() {
        while (!_cancellationToken->isCanceled()) {
            try {
                _cancellationToken->sleep( std::chrono::milliseconds(1000));
            } catch (const privmx::utils::OperationCancelledException& e) {
                break;
            }
            std::vector<std::string> keysToDelete;
            auto key = _keysStrage.get(_currentKeyId).value();
            if(key->creation_time + key->TTL - std::chrono::milliseconds(MAX_UPDATE_TIMEOUT+1000) < std::chrono::system_clock::now() && !_keyUpdateInProgress) {
                updateKey();
            }

            _keysStrage.forAll([&](std::string key, std::shared_ptr<StreamEncKey> value) {
                if(value->creation_time + value->TTL < std::chrono::system_clock::now()) {
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
    _internalContextEventManager->subscribeFor(_contextId);
}

StreamKeyManager::~StreamKeyManager() {
    _cancellationToken->cancel();
    _internalContextEventManager->unsubscribeFrom(_contextId);
    PRIVMX_DEBUG("STREAMS", "KEY-MANAGER", "Successfully Deconstructed : " + _streamRoomId);
}
std::vector<privmx::endpoint::stream::Key> StreamKeyManager::getCurrentWebRtcKeys() {
    return _currentWebRtcKeys;
}

int64_t StreamKeyManager::addKeyUpdateCallback(std::function<void(const std::vector<privmx::endpoint::stream::Key>&)> keyUpdateCallback) {
    int64_t id = ++_nextKeyUpdateCallbackId;
    _webRtcKeyUpdateCallbacks.set(id, keyUpdateCallback);
    keyUpdateCallback(_currentWebRtcKeys);
    return id;
}

void StreamKeyManager::removeKeyUpdateCallback(int64_t keyUpdateCallbackId) {
    _webRtcKeyUpdateCallbacks.erase(keyUpdateCallbackId);
}

void StreamKeyManager::respondToEvent(dynamic::StreamKeyManagementEvent event, const std::string& userId, const std::string& userPubKey) {
    std::cout << "event.subtype(): " << event.subtype() << std::endl;
    if(event.subtype() == "RequestKeyEvent") {
        respondToRequestKey(userId, userPubKey);
    } else if(event.subtype() == "RequestKeyRespondEvent") {
        setRequestKeyResult(privmx::utils::TypedObjectFactory::createObjectFromVar<dynamic::RequestKeyRespondEvent>(event));
    } else if(event.subtype() == "UpdateKeyEvent") {
        respondToUpdateRequest(privmx::utils::TypedObjectFactory::createObjectFromVar<dynamic::UpdateKeyEvent>(event), userId, userPubKey);
    } else if(event.subtype() == "UpdateKeyACKEvent") {
        respondUpdateKeyConfirmation(privmx::utils::TypedObjectFactory::createObjectFromVar<dynamic::UpdateKeyACKEvent>(event), userPubKey);
    }
}

void StreamKeyManager::requestKey(const std::vector<privmx::endpoint::core::UserWithPubKey>& users) {
    // prepare data to send
    dynamic::RequestKeyEvent request = privmx::utils::TypedObjectFactory::createNewObject<dynamic::RequestKeyEvent>();
    request.subtype("RequestKeyEvent");
    // send to users
    sendStreamKeyManagementEvent(request, users);
}

void StreamKeyManager::respondToRequestKey(const std::string& userId, const std::string& userPubKey) {
    // data
    auto currentKey = _keyForUpdate;

    dynamic::StreamEncKey streamEncKey = privmx::utils::TypedObjectFactory::createNewObject<dynamic::StreamEncKey>();
    streamEncKey.keyId(currentKey->key.id);
    streamEncKey.key(privmx::utils::Base64::from(currentKey->key.key));
    auto ttl = currentKey->creation_time + currentKey->TTL - std::chrono::system_clock::now();
    std::chrono::milliseconds ttlMilli = std::chrono::duration_cast<std::chrono::milliseconds>(ttl);
    streamEncKey.TTL(ttlMilli.count());
    dynamic::RequestKeyRespondEvent respond = privmx::utils::TypedObjectFactory::createNewObject<dynamic::RequestKeyRespondEvent>();
    respond.subtype("RequestKeyRespondEvent");
    respond.encKey(streamEncKey);
    // send data by event
    sendStreamKeyManagementEvent(respond, {privmx::endpoint::core::UserWithPubKey{.userId=userId, .pubKey=userPubKey}});
    _connectedUsers.push_back(privmx::endpoint::core::UserWithPubKey{.userId=userId, .pubKey=userPubKey});
}

void StreamKeyManager::setRequestKeyResult(dynamic::RequestKeyRespondEvent result) {
    //validate data
    auto newKey = result.encKey();
    // add new key
    _keysStrage.set(
        newKey.keyId(),
        std::make_shared<StreamEncKey>(
            StreamEncKey{
                .key=privmx::endpoint::core::EncKey{.id=newKey.keyId(), .key=privmx::utils::Base64::toString(newKey.key())},
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
    _keyUpdateInProgress = true;
    auto newKey = prepareCurrenKeyToUpdate();
    _userUpdateKeyConfirmationStatus.clear();
    for(auto user : _connectedUsers) {
        _userUpdateKeyConfirmationStatus.set(user.pubKey, false);
    }
    // prepare data to send
    dynamic::UpdateKeyEvent respond = privmx::utils::TypedObjectFactory::createNewObject<dynamic::UpdateKeyEvent>();
    respond.subtype("UpdateKeyEvent");
    respond.encKey(newKey);
    // send to users
    sendStreamKeyManagementEvent(respond, _connectedUsers);
    //thread for timeout and update
    std::thread t([&]() {
        std::unique_lock<std::mutex> lock(_updateKeyMutex);
        _updateKeyCV.wait_until(lock, std::chrono::system_clock::now() + std::chrono::milliseconds(MAX_UPDATE_TIMEOUT));
        _keysStrage.set(_keyForUpdate->key.id, _keyForUpdate);
        _currentKeyId = _keyForUpdate->key.id;
        updateWebRtcKeyStore();
        _keyUpdateInProgress = false;
    }); 
    t.detach();
}
//
void StreamKeyManager::respondToUpdateRequest(dynamic::UpdateKeyEvent request, const std::string& userId, const std::string& userPubKey) {
    //extract key
    auto newKey = request.encKey();
    // add new key
    _keysStrage.set(
        newKey.keyId(),
        std::make_shared<StreamEncKey>(
            StreamEncKey{
                .key=privmx::endpoint::core::EncKey{.id=newKey.keyId(), .key=privmx::utils::Base64::toString(newKey.key())},
                .creation_time=std::chrono::system_clock::now(), 
                .TTL=std::chrono::milliseconds(newKey.TTL())
            }
        )
    );
    updateWebRtcKeyStore();
    // prepare ack data
    dynamic::UpdateKeyACKEvent ack = privmx::utils::TypedObjectFactory::createNewObject<dynamic::UpdateKeyACKEvent>();
    ack.subtype("UpdateKeyACKEvent");
    ack.keyId(newKey.keyId());
    // send confirmation event
    sendStreamKeyManagementEvent(ack, {privmx::endpoint::core::UserWithPubKey{.userId=userId, .pubKey=userPubKey}});
}

void StreamKeyManager::respondUpdateKeyConfirmation(dynamic::UpdateKeyACKEvent ack, const std::string& userPubKey) {
    if(_keyForUpdate->key.id == ack.keyId()) {
        _userUpdateKeyConfirmationStatus.erase(userPubKey);
        if (_userUpdateKeyConfirmationStatus.size() == 0) {
            _updateKeyCV.notify_all();
        }
    }
}

dynamic::NewStreamEncKey StreamKeyManager::prepareCurrenKeyToUpdate() {    
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
    dynamic::NewStreamEncKey result = privmx::utils::TypedObjectFactory::createNewObject<dynamic::NewStreamEncKey>();
    result.oldKeyId(currentKey->key.id);
    
    if( currentKey->creation_time + currentKey->TTL >= std::chrono::system_clock::now() - std::chrono::milliseconds(MAX_UPDATE_TIMEOUT)) {
        result.oldKeyTTL(std::chrono::milliseconds(MAX_UPDATE_TIMEOUT).count());

    } else {
        auto ttl = currentKey->creation_time + currentKey->TTL - std::chrono::system_clock::now();
        std::chrono::milliseconds ttlMilli = std::chrono::duration_cast<std::chrono::milliseconds>(ttl);
        result.oldKeyTTL(ttlMilli.count());
    }
    result.key(privmx::utils::Base64::from(_keyForUpdate->key.key));
    result.keyId(_keyForUpdate->key.id);
    auto ttl = _keyForUpdate->creation_time + _keyForUpdate->TTL - std::chrono::system_clock::now();
    std::chrono::milliseconds ttlMilli = std::chrono::duration_cast<std::chrono::milliseconds>(ttl);
    result.TTL(ttlMilli.count());
    return result;
}

void StreamKeyManager::sendStreamKeyManagementEvent(dynamic::StreamCustomEventData data, const std::vector<privmx::endpoint::core::UserWithPubKey>& users) {
    data.streamRoomId(_streamRoomId);
    core::InternalContextEventData eventData = {.type="StreamKeyManagementEvent", .data= privmx::endpoint::core::Buffer::from(utils::Utils::stringifyVar(data))};
    std::cout << users.size() << std::endl;
    _internalContextEventManager->sendEvent(_contextId, eventData, users);
}

void StreamKeyManager::updateWebRtcKeyStore() {
    std::vector<privmx::endpoint::stream::Key> webRtcKeys;
    _keysStrage.forAll([&]([[maybe_unused]]std::string key, std::shared_ptr<StreamEncKey> value) {
        privmx::endpoint::stream::Key webRtcKey {
            .keyId = value->key.id,
            .key =  value->key.key,
            .type = value->key.id == _currentKeyId ? privmx::endpoint::stream::KeyType::LOCAL : privmx::endpoint::stream::KeyType::REMOTE
        };
        webRtcKeys.push_back(webRtcKey);
    });
    _currentWebRtcKeys = webRtcKeys;
    _webRtcKeyUpdateCallbacks.forAll([&]([[maybe_unused]]int64_t key, std::function<void(const std::vector<privmx::endpoint::stream::Key>&)> value) {
        value(_currentWebRtcKeys);
    });
}
