/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/event/encryptors/event/EventDataSchemaStrategyV5.hpp"

#include <privmx/crypto/ecc/PublicKeyCache.hpp>
#include <privmx/endpoint/core/Buffer.hpp>

#include "privmx/endpoint/event/Constants.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::event;

DecryptedEventDataV5 EventDataSchemaStrategyV5::decrypt(
    const server::ContextCustomEventData& model,
    const core::DecryptedEncKey& encKey
) const {
    auto authorPubKey = privmx::crypto::PublicKeyCache::getInstance()->fromBase58DER(model.author.pub);
    auto encryptedData = server::EncryptedContextEventDataV5::fromJSON(model.eventData);
    return _encryptor.decrypt(encryptedData, authorPubKey, encKey.key);
}

ContextCustomEventData EventDataSchemaStrategyV5::convert(
    const server::ContextCustomEventData& model,
    const DecryptedEventDataV5& raw
) const {
    return toContextCustomEventData(
        model, raw.data, core::toPublicError(raw.error), EventDataSchema::Version::VERSION_5
    );
}

ContextCustomEventData EventDataSchemaStrategyV5::makeErrorResult(
    const server::ContextCustomEventData& model,
    const std::optional<core::Error>& error
) const {
    return toContextCustomEventData(model, {}, error, EventDataSchema::Version::VERSION_5);
}

ContextCustomEventData EventDataSchemaStrategyV5::toContextCustomEventData(
    const server::ContextCustomEventData& raw,
    const core::Buffer& payload,
    const std::optional<core::Error>& error,
    int64_t schemaVersion
) {
    return ContextCustomEventData{
        .contextId = raw.id, .userId = raw.author.id, .payload = payload, .error = error, .schemaVersion = schemaVersion
    };
}
