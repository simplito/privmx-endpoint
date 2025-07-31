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
#include <privmx/endpoint/core/CoreException.hpp>

#define UPDATE_INTERVAL 1000*1
#define MAX_UPDATE_TIMEOUT 1000*5
#define MAX_STD_KEY_TTL 1000*3+MAX_UPDATE_TIMEOUT+UPDATE_INTERVAL

using namespace privmx::endpoint::stream; 

StreamKeyManager::StreamKeyManager(
    std::shared_ptr<event::EventApiImpl> eventApi,
    std::shared_ptr<core::KeyProvider> keyProvider, 
    std::shared_ptr<ServerApi> serverApi,
    privmx::crypto::PrivateKey userPrivKey, 
    const std::string& streamRoomId,
    const std::string& contextId
) : _eventApi(eventApi), _keyProvider(keyProvider), _serverApi(serverApi), _userPrivKey(userPrivKey), _streamRoomId(streamRoomId), _contextId(contextId) {
    _userPubKey = _userPrivKey.getPublicKey();
    // generate curren key
    auto currentKey = _keyProvider->generateKey();
    _keyForUpdate = std::make_shared<StreamEncKey>(StreamEncKey{
        .key=currentKey, 
        .creation_time=std::chrono::system_clock::now(), 
        .TTL=std::chrono::milliseconds(MAX_STD_KEY_TTL)
    });
    _keysStrage.insert_or_assign(_keyForUpdate->key.id, _keyForUpdate);
    _currentKeyId = _keyForUpdate->key.id;
    updateWebRtcKeyStore();
    // ->setKey(currentKey.id, currentKey.key);
    _cancellationToken = privmx::utils::CancellationToken::create();
    // create thread to remove old keys
    _keyCollector = std::thread([&](privmx::utils::CancellationToken::Ptr token) {
        try {
            while (!token->isCancelled()) {

                PRIVMX_DEBUG("STREAMS", "KEY-MANAGER", "key update Loop")  
                _cancellationToken->sleep( std::chrono::milliseconds(UPDATE_INTERVAL));
                
                std::shared_ptr<StreamKeyManager::StreamEncKey> key;
                {
                    std::shared_lock<std::shared_mutex> lock(_keysStrageMutex);
                    if (_keysStrage.find(_currentKeyId) != _keysStrage.end()) {
                        key = _keysStrage.at(_currentKeyId); 
                    }
                }
                if(!key || (key->creation_time + key->TTL - std::chrono::milliseconds(MAX_UPDATE_TIMEOUT+UPDATE_INTERVAL) < std::chrono::system_clock::now())) {
                    PRIVMX_DEBUG("STREAMS", "KEY-MANAGER", "updating current Key")
                    updateKey();
                }
            }
            std::cerr << "std::thread while-loop break" << std::endl;
        } catch (const core::Exception& e) {
            std::cerr << "Error on std::thread" << e.getFull() << std::endl;
        } catch (const std::exception& ex) {
            std::cerr << "Unknown exception" << ex.what() << std::endl;
        }
    }, _cancellationToken); 
    _eventApi->subscribeForInternalEvents(_contextId);
}

StreamKeyManager::~StreamKeyManager() {
    std::cerr << "Created _cancellationToken at StreamKeyManager deconstructor: " << _cancellationToken.get() << std::endl; // Debug by Patryk
    _cancellationToken->cancel();
    _updateKeyCV.notify_all();
    _eventApi->unsubscribeFromInternalEvents(_contextId);
    if(_keyCollector.joinable()) _keyCollector.join();
    // if(_keyUpdater.has_value()) if(_keyUpdater.value().joinable()) _keyUpdater.value().join();
    PRIVMX_DEBUG("STREAMS", "KEY-MANAGER", "Successfully Deconstructed : " + _streamRoomId);
}
std::vector<privmx::endpoint::stream::Key> StreamKeyManager::getCurrentWebRtcKeys() {
    return _currentWebRtcKeys;
}

int64_t StreamKeyManager::addKeyUpdateCallback(std::function<void(const std::vector<privmx::endpoint::stream::Key>&)> keyUpdateCallback) {
    int64_t id = ++_nextKeyUpdateCallbackId;
    {
        std::unique_lock<std::shared_mutex> lock(_webRtcKeyUpdateCallbacksMutex);
        _webRtcKeyUpdateCallbacks.insert_or_assign(id, keyUpdateCallback);
    }
    keyUpdateCallback(_currentWebRtcKeys);
    return id;
}

void StreamKeyManager::removeKeyUpdateCallback(int64_t keyUpdateCallbackId) {
    std::unique_lock<std::shared_mutex> lock(_webRtcKeyUpdateCallbacksMutex);
    _webRtcKeyUpdateCallbacks.erase(keyUpdateCallbackId);
}

void StreamKeyManager::respondToEvent(dynamic::StreamKeyManagementEvent event, const std::string& userId, const std::string& userPubKey) {

    PRIVMX_DEBUG("STREAMS", "KEY-MANAGER", "respondToEvent data: " + privmx::utils::Utils::stringifyVar(event));  
    if(event.subtype() == "RequestKeyEvent") {
        PRIVMX_DEBUG("STREAMS", "KEY-MANAGER", "respondToUpdateRequest updateWebRtcKeyStore");
        respondToRequestKey(userId, userPubKey);
    } else if(event.subtype() == "RequestKeyRespondEvent") {
        PRIVMX_DEBUG("STREAMS", "KEY-MANAGER", "respondToUpdateRequest updateWebRtcKeyStore");
        setRequestKeyResult(privmx::utils::TypedObjectFactory::createObjectFromVar<dynamic::RequestKeyRespondEvent>(event));
    } else if(event.subtype() == "UpdateKeyEvent") {
        PRIVMX_DEBUG("STREAMS", "KEY-MANAGER", "respondToUpdateRequest updateWebRtcKeyStore");
        respondToUpdateRequest(privmx::utils::TypedObjectFactory::createObjectFromVar<dynamic::UpdateKeyEvent>(event), userId, userPubKey);
    } else if(event.subtype() == "UpdateKeyACKEvent") {
        PRIVMX_DEBUG("STREAMS", "KEY-MANAGER", "respondToUpdateRequest updateWebRtcKeyStore");
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
    auto userWithPubKey = privmx::endpoint::core::UserWithPubKey{.userId=userId, .pubKey=userPubKey};
    sendStreamKeyManagementEvent(respond, {userWithPubKey});
    bool hasUser = false;
    std::unique_lock<std::mutex> lock(_connectedUsersMutex);
    for(auto& connectedUser : _connectedUsers) {
        if(userWithPubKey.pubKey == connectedUser.pubKey && userWithPubKey.userId == connectedUser.userId) {
            hasUser = true;
            break;
        }
    }
    if(!hasUser) _connectedUsers.push_back(userWithPubKey);
}

void StreamKeyManager::setRequestKeyResult(dynamic::RequestKeyRespondEvent result) {
    //validate data
    auto newKey = result.encKey();
    // add new key
    {
        std::unique_lock<std::shared_mutex> lock(_keysStrageMutex);
        _keysStrage.insert_or_assign(
            newKey.keyId(),
            std::make_shared<StreamEncKey>(
                StreamEncKey{
                    .key=privmx::endpoint::core::EncKey{.id=newKey.keyId(), .key=privmx::utils::Base64::toString(newKey.key())},
                    .creation_time=std::chrono::system_clock::now(), 
                    .TTL=std::chrono::milliseconds(newKey.TTL())
                }
            )
        );
    }
    PRIVMX_DEBUG("STREAMS", "KEY-MANAGER", "setRequestKeyResult updateWebRtcKeyStore");
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
    bool wait = false;
    {
        std::unique_lock<std::mutex> lock(_connectedUsersMutex);
        {
            std::unique_lock<std::shared_mutex> lock(_userUpdateKeyConfirmationStatusMutex);
            _userUpdateKeyConfirmationStatus.clear();
            
            for(auto user : _connectedUsers) {
                _userUpdateKeyConfirmationStatus.insert_or_assign(user.pubKey, false);
            }
        }
        // prepare data to send
        dynamic::UpdateKeyEvent respond = privmx::utils::TypedObjectFactory::createNewObject<dynamic::UpdateKeyEvent>();
        respond.subtype("UpdateKeyEvent");
        respond.encKey(newKey);
        // send to users
        if(!disableKeyUpdateForEncryptors) {
            sendStreamKeyManagementEvent(respond, _connectedUsers);
        }
        //update timeout
        if(_connectedUsers.size() > 0) {
            wait = true;
        }
    }

    std::unique_lock<std::mutex> lock(_updateKeyMutex);
    if(wait) {
        PRIVMX_DEBUG("STREAMS", "KEY-MANAGER", "updateKey _updateKeyCV.wait_for");
        _updateKeyCV.wait_for(lock, std::chrono::milliseconds(MAX_UPDATE_TIMEOUT));
        PRIVMX_DEBUG("STREAMS", "KEY-MANAGER", "updateKey _updateKeyCV.wait_for done");
    }
    if(!_cancellationToken->isCancelled()) {
        {
            std::unique_lock<std::shared_mutex> lock(_keysStrageMutex);
            _keysStrage.insert_or_assign(_keyForUpdate->key.id, _keyForUpdate);
            _currentKeyId = _keyForUpdate->key.id;
        }
        PRIVMX_DEBUG("STREAMS", "KEY-MANAGER", "updateKey updateWebRtcKeyStore");
        updateWebRtcKeyStore();
    }
}

void StreamKeyManager::respondToUpdateRequest(dynamic::UpdateKeyEvent request, const std::string& userId, const std::string& userPubKey) {
    //extract key
    auto newKey = request.encKey();
    // add new key
    {
        std::unique_lock<std::shared_mutex> lock(_keysStrageMutex);
        _keysStrage.insert_or_assign(
            newKey.keyId(),
            std::make_shared<StreamEncKey>(
                StreamEncKey{
                    .key=privmx::endpoint::core::EncKey{.id=newKey.keyId(), .key=privmx::utils::Base64::toString(newKey.key())},
                    .creation_time=std::chrono::system_clock::now(), 
                    .TTL=std::chrono::milliseconds(newKey.TTL())
                }
            )
        );
    }
    PRIVMX_DEBUG("STREAMS", "KEY-MANAGER", "respondToUpdateRequest updateWebRtcKeyStore");
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
        std::unique_lock<std::shared_mutex> lock(_userUpdateKeyConfirmationStatusMutex);
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
    std::shared_ptr<StreamKeyManager::StreamEncKey> currentKey;
    {
        std::shared_lock<std::shared_mutex> lock(_keysStrageMutex);
        currentKey = _keysStrage.at(_currentKeyId);
    }
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
    event::InternalContextEventDataV1 event = {.type="StreamKeyManagementEvent", .data= privmx::endpoint::core::Buffer::from(utils::Utils::stringifyVar(data))};

    PRIVMX_DEBUG("STREAMS", "KEY-MANAGER", "sendStreamKeyManagementEvent data: " + privmx::utils::Utils::stringifyVar(data));
    _eventApi->emitEventInternal(_contextId, event, users);

}

void StreamKeyManager::updateWebRtcKeyStore() {
    removeOldKeyFormKeysStrage();
    std::vector<privmx::endpoint::stream::Key> webRtcKeys;
    {
        std::shared_lock<std::shared_mutex> lock(_keysStrageMutex);
        PRIVMX_DEBUG("STREAMS", "KEY-MANAGER", "updateWebRtcKeyStore key_list_size : " + std::to_string(_keysStrage.size()));
        for(auto& key: _keysStrage) {
            privmx::endpoint::stream::Key webRtcKey {
                .keyId = key.second->key.id,
                .key =  core::Buffer::from(key.second->key.key),
                .type = key.second->key.id == _currentKeyId ? privmx::endpoint::stream::KeyType::LOCAL : privmx::endpoint::stream::KeyType::REMOTE
            };
            webRtcKeys.push_back(webRtcKey);
        };
    }
    _currentWebRtcKeys = webRtcKeys;
    if(!disableKeyUpdateForEncryptors) {
        std::shared_lock<std::shared_mutex> lock(_webRtcKeyUpdateCallbacksMutex);
        for(auto& webRtcKeyUpdateCallback: _webRtcKeyUpdateCallbacks) {
            webRtcKeyUpdateCallback.second(_currentWebRtcKeys);
        };
    }
}

void StreamKeyManager::removeOldKeyFormKeysStrage() {
    std::vector<std::string> keysToDelete;
    {
        std::shared_lock<std::shared_mutex> lock(_keysStrageMutex);
        for(auto& key: _keysStrage) {
            if(key.second->creation_time + key.second->TTL < std::chrono::system_clock::now()) {
                keysToDelete.push_back(key.first);
            }
        };
    }
    if(keysToDelete.size() > 0) {
        {
            std::unique_lock<std::shared_mutex> lock(_keysStrageMutex);
            for(auto& keyToDelete: keysToDelete) {
                _keysStrage.erase(keyToDelete);
            }
        }
    }
}