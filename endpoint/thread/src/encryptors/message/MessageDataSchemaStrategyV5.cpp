/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/thread/encryptors/message/MessageDataSchemaStrategyV5.hpp"
#include "privmx/endpoint/thread/encryptors/message/MessageDataSchemaMapper.hpp"

#include <privmx/endpoint/core/CoreConstants.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>

#include "privmx/endpoint/thread/Constants.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::thread;

server::EncryptedMessageDataV5 MessageDataSchemaStrategyV5::encrypt(
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const core::Buffer& data,
    const privmx::crypto::PrivateKey& userPrivKey,
    const std::string& key,
    const core::DataIntegrityObject& dio
) const {
    MessageDataToEncryptV5 messageData{
        .publicMeta = publicMeta, .privateMeta = privateMeta, .data = data, .internalMeta = std::nullopt, .dio = dio
    };
    return _encryptor.encrypt(messageData, userPrivKey, key);
}

server::EncryptedMessageDataV5 MessageDataSchemaStrategyV5::getEncryptedData(
    const server::Message& model
) const {
    return server::EncryptedMessageDataV5::fromJSON(model.data);
}

std::tuple<Message, core::DataIntegrityObject> MessageDataSchemaStrategyV5::convert(
    const server::Message& message,
    const DecryptedMessageDataV5& raw
) const {
    return {
        MessageDataSchemaMapper::toLibMessage(
            message, raw.publicMeta, raw.privateMeta, raw.data, raw.authorPubKey, raw.statusCode,
            MessageDataSchema::Version::VERSION_5
        ),
        raw.dio
    };
}

std::tuple<Message, core::DataIntegrityObject> MessageDataSchemaStrategyV5::makeErrorResult(
    const server::Message& message,
    int64_t errorCode
) const {
    return {
        MessageDataSchemaMapper::toLibMessage(
            message, {}, {}, {}, {}, errorCode, MessageDataSchema::Version::VERSION_5
        ),
        core::DataIntegrityObject{}
    };
}
