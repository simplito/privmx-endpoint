/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/event/encryptors/event/EventDataSchemaStrategyV5.hpp"

#include <privmx/crypto/ecc/PublicKey.hpp>
#include <privmx/endpoint/core/Buffer.hpp>

#include "privmx/endpoint/event/Constants.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::event;

DecryptedEventDataV5 EventDataSchemaStrategyV5::decrypt(
    const server::ContextCustomEventData& model,
    const core::DecryptedEncKey& encKey
) const {
    auto authorPubKey = privmx::crypto::PublicKey::fromBase58DER(model.author.pub);
    auto encryptedData = server::EncryptedContextEventDataV5::fromJSON(model.eventData);
    return _encryptor.decrypt(encryptedData, authorPubKey, encKey.key);
}

ContextCustomEventData EventDataSchemaStrategyV5::convert(
    const server::ContextCustomEventData& model,
    const DecryptedEventDataV5& raw
) const {
    return toContextCustomEventData(model, raw.data, raw.statusCode, EventDataSchema::Version::VERSION_5);
}

ContextCustomEventData EventDataSchemaStrategyV5::makeErrorResult(
    const server::ContextCustomEventData& model,
    int64_t errorCode
) const {
    return toContextCustomEventData(model, {}, errorCode, EventDataSchema::Version::VERSION_5);
}

ContextCustomEventData EventDataSchemaStrategyV5::toContextCustomEventData(
    const server::ContextCustomEventData& raw,
    const core::Buffer& payload,
    int64_t statusCode,
    int64_t schemaVersion
) {
    return ContextCustomEventData{
        .contextId = raw.id,
        .userId = raw.author.id,
        .payload = payload,
        .statusCode = statusCode,
        .schemaVersion = schemaVersion
    };
}
