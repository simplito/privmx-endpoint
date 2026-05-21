/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/thread/encryptors/message/MessageDataSchemaStrategyV4.hpp"
#include "privmx/endpoint/thread/encryptors/message/MessageDataSchemaMapper.hpp"

#include <privmx/endpoint/core/CoreConstants.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>

#include "privmx/endpoint/thread/Constants.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::thread;

server::EncryptedMessageDataV4 MessageDataSchemaStrategyV4::encrypt(
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const core::Buffer& data,
    const privmx::crypto::PrivateKey& userPrivKey,
    const std::string& key
) const {
    MessageDataToEncryptV4 messageData{
        .publicMeta = publicMeta, .privateMeta = privateMeta, .data = data, .internalMeta = std::nullopt
    };
    return _encryptor.encrypt(messageData, userPrivKey, key);
}

DecryptedMessageDataV4 MessageDataSchemaStrategyV4::decrypt(
    const server::Message& message,
    const core::DecryptedEncKey& encKey
) const {
    auto encryptedMessageData = server::EncryptedMessageDataV4::fromJSON(message.data);
    return _encryptor.decrypt(encryptedMessageData, encKey.key);
}

std::tuple<Message, core::DataIntegrityObject> MessageDataSchemaStrategyV4::convert(
    const server::Message& message,
    const DecryptedMessageDataV4& raw
) const {
    const auto& lastAuthor = message.updates.empty() ? message.author : message.updates.back().author;
    const auto& lastDate = message.updates.empty() ? message.createDate : message.updates.back().createDate;
    return {
        MessageDataSchemaMapper::toLibMessage(
            message, raw.publicMeta, raw.privateMeta, raw.data, raw.authorPubKey, raw.statusCode,
            MessageDataSchema::Version::VERSION_4
        ),
        core::DataIntegrityObject{
            .creatorUserId = lastAuthor,
            .creatorPubKey = raw.authorPubKey,
            .contextId = message.contextId,
            .resourceId = message.resourceId,
            .timestamp = lastDate,
            .randomId = std::string(),
            .containerId = message.threadId,
            .containerResourceId = std::string(),
            .bridgeIdentity = std::nullopt
        }
    };
}

std::tuple<Message, core::DataIntegrityObject> MessageDataSchemaStrategyV4::makeErrorResult(
    const server::Message& message,
    int64_t errorCode
) const {
    return {
        MessageDataSchemaMapper::toLibMessage(
            message, {}, {}, {}, {}, errorCode, MessageDataSchema::Version::VERSION_4
        ),
        core::DataIntegrityObject{}
    };
}
