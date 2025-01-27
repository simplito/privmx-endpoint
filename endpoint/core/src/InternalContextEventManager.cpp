/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/core/InternalContextEventManager.hpp"
#include "privmx/endpoint/core/Buffer.hpp"
#include <privmx/crypto/EciesEncryptor.hpp>
#include <privmx/crypto/Crypto.hpp>
#include <privmx/utils/Utils.hpp>
#include <privmx/utils/Utils.hpp>


using namespace privmx::endpoint::core;

InternalContextEventManager::InternalContextEventManager(
    const privmx::crypto::PrivateKey& userPrivKey, 
    privfs::RpcGateway::Ptr gateway,
    std::shared_ptr<SubscriptionHelper> contextSubscriptionHelper
) : _userPrivKey(userPrivKey), _gateway(gateway), _contextSubscriptionHelper(contextSubscriptionHelper) {}

void InternalContextEventManager::sendEvent(const std::string& contextId, InternalContextEventData data, const std::vector<UserWithPubKey>& users) {
    auto key = privmx::crypto::Crypto::randomBytes(32);
    server::EncryptedInternalContextEventData encryptedEventData = privmx::utils::TypedObjectFactory::createNewObject<server::EncryptedInternalContextEventData>();
    encryptedEventData.type(data.type);
    encryptedEventData.encryptedData(_dataEncryptor.signAndEncryptAndEncode( data.data, _userPrivKey, key));
    utils::List<server::UserKey> userKeys = utils::TypedObjectFactory::createNewList<server::UserKey>();
    for (auto user : users) {
        server::UserKey userKey = utils::TypedObjectFactory::createNewObject<server::UserKey>();
        userKey.id(user.userId);
        userKey.key(crypto::EciesEncryptor::encryptToBase64(crypto::PublicKey::fromBase58DER(user.pubKey), key));
        userKeys.add(userKey);
    }
    server::CustomEventModel model = privmx::utils::TypedObjectFactory::createNewObject<server::CustomEventModel>();
    model.contextId(contextId);
    model.data(encryptedEventData);
    model.channel("internal");
    model.users(userKeys);
    std::cout << utils::Utils::stringifyVar(model) << std::endl; 
    _gateway->request("context.contextSendCustomEvent", model);
}

bool InternalContextEventManager::isInternalContextEvent(const std::string& type, const std::string& channel, Poco::JSON::Object::Ptr eventData, const std::optional<std::string>& internalContextEventType) {
    //check if type == "custom" and channel == "context/<contextId>/internal"
    if(type == "custom" && channel.length() >= 8+9 && channel.substr(0, 8) == "context/" && channel.substr(channel.length()-9, 9) == "/internal") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::ContextCustomEventData>(eventData);
        if(!raw.idEmpty() && _contextSubscriptionHelper->hasSubscriptionForElementCustom(raw.id(), "internal")) {
            if(raw.eventData().type() == typeid(Poco::JSON::Object::Ptr)) {
                auto rawEventDataJSON = raw.eventData().extract<Poco::JSON::Object::Ptr>();
                if(rawEventDataJSON->has("type")) {
                    if(!internalContextEventType.has_value()) {
                        return true;
                    } else {
                        if(rawEventDataJSON->getValue<std::string>("type") == internalContextEventType.value()) {
                            return true;
                        }
                    }
                }
            }
        }
    }
    return false;
}

InternalContextEventData InternalContextEventManager::extractEventData(const Poco::JSON::Object::Ptr& eventData) {
    auto raw = utils::TypedObjectFactory::createObjectFromVar<server::ContextCustomEventData>(eventData);
    auto rawEventData = utils::TypedObjectFactory::createObjectFromVar<server::EncryptedInternalContextEventData>(raw.eventData());
    auto encKey = privmx::crypto::EciesEncryptor::decryptFromBase64(_userPrivKey, raw.key());
    auto decryptedData = _dataEncryptor.decodeAndDecryptAndVerify(rawEventData.encryptedData(), _userPrivKey.getPublicKey(), encKey);
    return InternalContextEventData{.type=rawEventData.type(), .data=decryptedData};
}

void InternalContextEventManager::subscribeFor(const std::string& contextId) {
    _contextSubscriptionHelper->subscribeForElementCustom(contextId, INTERNAL_CHANNEL_NAME);
}

void InternalContextEventManager::unsubscribeFrom(const std::string& contextId) {
    _contextSubscriptionHelper->subscribeForElementCustom(contextId, INTERNAL_CHANNEL_NAME);
}