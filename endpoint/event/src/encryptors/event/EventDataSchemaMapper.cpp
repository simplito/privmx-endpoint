/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/event/encryptors/event/EventDataSchemaMapper.hpp"

#include <Poco/JSON/Object.h>
#include <privmx/crypto/ecc/PublicKeyCache.hpp>
#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/CoreConstants.hpp>

#include "privmx/endpoint/event/EventException.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::event;

EventDataSchemaMapper::EventDataSchemaMapper(
    const privmx::crypto::PrivateKey& userPrivKey,
    const core::Connection& connection
)
    : _userPrivKey(userPrivKey), _connection(connection), _eventKeyProvider(userPrivKey) {
    _strategyV5 = std::make_shared<EventDataSchemaStrategyV5>();
    _strategyMapper.registerStrategy(EventDataSchema::Version::VERSION_5, _strategyV5);
}

Poco::Dynamic::Var EventDataSchemaMapper::encrypt(
    const std::string& contextId,
    const core::Buffer& data,
    const std::optional<std::string>& type,
    const std::string& key
) {
    auto toEncrypt = ContextEventDataToEncryptV5{
        ContextEventDataV5{.data = data, .type = type, .dio = _connection.getImpl()->createDIO(contextId, "")}
    };
    return _encryptorV5.encrypt(toEncrypt, _userPrivKey, key).toJSON();
}

ContextCustomEventData EventDataSchemaMapper::decrypt(const server::ContextCustomEventData& rawEvent) {
    if (getDataStructureVersion(rawEvent) != EventDataSchema::Version::VERSION_5) {
        return makeErrorResult(rawEvent, core::toPublicError(InvalidEncryptedEventDataVersionException()));
    }
    auto authorPubKey = privmx::crypto::PublicKeyCache::getInstance()->fromBase58DER(rawEvent.author.pub);
    auto decryptedKey = _eventKeyProvider.decryptKey(rawEvent.key, authorPubKey);
    if (decryptedKey.error) {
        return makeErrorResult(rawEvent, core::toPublicError(decryptedKey.error));
    }
    core::DecryptedEncKey encKey;
    encKey.key = decryptedKey.key;
    try {
        auto raw = _strategyV5->decrypt(rawEvent, encKey);
        if (raw.statusCode() == 0 && !verifyDecryptedEventData(raw)) {
            raw.error = core::asError(privmx::endpoint::core::UserVerificationFailureException());
        }
        return _strategyV5->convert(rawEvent, raw);
    } catch (const core::Exception& e) {
        return makeErrorResult(rawEvent, core::toPublicError(e));
    } catch (...) {
        return makeErrorResult(rawEvent, core::toPublicError(*core::unknownError("decrypting the context event")));
    }
}

DecryptedInternalContextEventDataV1 EventDataSchemaMapper::decryptInternal(
    const server::ContextCustomEventData& rawEvent
) {
    DecryptedInternalContextEventDataV1 result;
    result.dataStructureVersion = EventDataSchema::Version::VERSION_5;
    if (getDataStructureVersion(rawEvent) != EventDataSchema::Version::VERSION_5) {
        result.error = core::asError(InvalidEncryptedEventDataVersionException());
        return result;
    }
    auto authorPubKey = privmx::crypto::PublicKeyCache::getInstance()->fromBase58DER(rawEvent.author.pub);
    auto decryptedKey = _eventKeyProvider.decryptKey(rawEvent.key, authorPubKey);
    result.error = decryptedKey.error;
    if (result.error)
        return result;
    core::DecryptedEncKey encKey;
    encKey.key = decryptedKey.key;
    try {
        auto raw = _strategyV5->decrypt(rawEvent, encKey);
        result.error = raw.error;
        result.data = raw.data;
        result.type = raw.type.has_value() ? raw.type.value() : "";
        if (!result.error && !verifyDecryptedEventData(raw)) {
            result.error = core::asError(privmx::endpoint::core::UserVerificationFailureException());
        }
    } catch (const core::Exception& e) { result.error = core::asError(e); } catch (...) {
        result.error = core::unknownError("decrypting the internal context event");
    }
    return result;
}

bool EventDataSchemaMapper::verifyDecryptedEventData(const DecryptedEventDataV5& data) {
    std::vector<core::VerificationRequest> verifierInput{};
    verifierInput.push_back(
        core::VerificationRequest{
            .contextId = data.dio.contextId,
            .senderId = data.dio.creatorUserId,
            .senderPubKey = data.dio.creatorPubKey,
            .date = data.dio.timestamp,
            .bridgeIdentity = data.dio.bridgeIdentity
        }
    );
    auto verified = _connection.getImpl()->getUserVerifier()->verify(verifierInput);
    return verified[0];
}

EventDataSchema::Version EventDataSchemaMapper::getDataStructureVersion(
    const server::ContextCustomEventData& rawEvent
) {
    if (rawEvent.eventData.type() == typeid(Poco::JSON::Object::Ptr))
        return EventDataSchema::Version::VERSION_5;
    return EventDataSchema::Version::UNKNOWN;
}

ContextCustomEventData EventDataSchemaMapper::makeErrorResult(
    const server::ContextCustomEventData& rawEvent,
    const std::optional<core::Error>& error
) {
    return ContextCustomEventData{
        .contextId = rawEvent.id,
        .userId = rawEvent.author.id,
        .payload = {},
        .error = error,
        .schemaVersion = EventDataSchema::Version::UNKNOWN
    };
}
