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
#include <privmx/crypto/ecc/PublicKey.hpp>
#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/CoreConstants.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>

#include "privmx/endpoint/event/EventException.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::event;

EventDataSchemaMapper::EventDataSchemaMapper(
    const privmx::crypto::PrivateKey& userPrivKey,
    const core::Connection& connection
) : _userPrivKey(userPrivKey), _connection(connection), _eventKeyProvider(userPrivKey) {
    _strategyV5 = std::make_shared<EventDataSchemaStrategyV5>();
    _strategyMapper.registerStrategy(EventDataSchema::Version::VERSION_5, _strategyV5);
}

Poco::Dynamic::Var EventDataSchemaMapper::encrypt(
    const std::string& contextId,
    const core::Buffer& data,
    const std::optional<std::string>& type,
    const std::string& key
) {
    auto toEncrypt = ContextEventDataToEncryptV5{ContextEventDataV5{
        .data = data, .type = type, .dio = _connection.getImpl()->createDIO(contextId, "")
    }};
    return _encryptorV5.encrypt(toEncrypt, _userPrivKey, key).toJSON();
}

ContextCustomEventData EventDataSchemaMapper::decrypt(const server::ContextCustomEventData& rawEvent) {
    if (getDataStructureVersion(rawEvent) != EventDataSchema::Version::VERSION_5) {
        return makeErrorResult(rawEvent, InvalidEncryptedEventDataVersionException().getCode());
    }
    auto authorPubKey = privmx::crypto::PublicKey::fromBase58DER(rawEvent.author.pub);
    auto decryptedKey = _eventKeyProvider.decryptKey(rawEvent.key, authorPubKey);
    if (decryptedKey.statusCode != 0) {
        return makeErrorResult(rawEvent, decryptedKey.statusCode);
    }
    core::DecryptedEncKey encKey;
    encKey.key = decryptedKey.key;
    encKey.statusCode = 0;
    try {
        auto raw = _strategyV5->decrypt(rawEvent, encKey);
        if (raw.statusCode == 0 && !verifyDecryptedEventData(raw)) {
            raw.statusCode = core::ExceptionConverter::getCodeOfUserVerificationFailureException();
        }
        return _strategyV5->convert(rawEvent, raw);
    } catch (const core::Exception& e) {
        return makeErrorResult(rawEvent, e.getCode());
    } catch (const privmx::utils::PrivmxException& e) {
        return makeErrorResult(rawEvent, core::ExceptionConverter::convert(e).getCode());
    } catch (...) {
        return makeErrorResult(rawEvent, ENDPOINT_CORE_EXCEPTION_CODE);
    }
}

DecryptedInternalContextEventDataV1 EventDataSchemaMapper::decryptInternal(
    const server::ContextCustomEventData& rawEvent
) {
    DecryptedInternalContextEventDataV1 result;
    result.dataStructureVersion = EventDataSchema::Version::VERSION_5;
    if (getDataStructureVersion(rawEvent) != EventDataSchema::Version::VERSION_5) {
        result.statusCode = InvalidEncryptedEventDataVersionException().getCode();
        return result;
    }
    auto authorPubKey = privmx::crypto::PublicKey::fromBase58DER(rawEvent.author.pub);
    auto decryptedKey = _eventKeyProvider.decryptKey(rawEvent.key, authorPubKey);
    result.statusCode = decryptedKey.statusCode;
    if (result.statusCode != 0) return result;
    core::DecryptedEncKey encKey;
    encKey.key = decryptedKey.key;
    encKey.statusCode = 0;
    try {
        auto raw = _strategyV5->decrypt(rawEvent, encKey);
        result.statusCode = raw.statusCode;
        result.data = raw.data;
        result.type = raw.type.has_value() ? raw.type.value() : "";
        if (result.statusCode == 0 && !verifyDecryptedEventData(raw)) {
            result.statusCode = core::ExceptionConverter::getCodeOfUserVerificationFailureException();
        }
    } catch (const core::Exception& e) {
        result.statusCode = e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        result.statusCode = core::ExceptionConverter::convert(e).getCode();
    } catch (...) {
        result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
    }
    return result;
}

bool EventDataSchemaMapper::verifyDecryptedEventData(const DecryptedEventDataV5& data) {
    std::vector<core::VerificationRequest> verifierInput{};
    verifierInput.push_back(core::VerificationRequest{
        .contextId = data.dio.contextId,
        .senderId = data.dio.creatorUserId,
        .senderPubKey = data.dio.creatorPubKey,
        .date = data.dio.timestamp,
        .bridgeIdentity = data.dio.bridgeIdentity
    });
    auto verified = _connection.getImpl()->getUserVerifier()->verify(verifierInput);
    return verified[0];
}

EventDataSchema::Version EventDataSchemaMapper::getDataStructureVersion(
    const server::ContextCustomEventData& rawEvent
) {
    if (rawEvent.eventData.type() == typeid(Poco::JSON::Object::Ptr)) return EventDataSchema::Version::VERSION_5;
    return EventDataSchema::Version::UNKNOWN;
}

ContextCustomEventData EventDataSchemaMapper::makeErrorResult(
    const server::ContextCustomEventData& rawEvent,
    int64_t errorCode
) {
    return ContextCustomEventData{
        .contextId = rawEvent.id,
        .userId = rawEvent.author.id,
        .payload = {},
        .statusCode = errorCode,
        .schemaVersion = EventDataSchema::Version::UNKNOWN
    };
}
