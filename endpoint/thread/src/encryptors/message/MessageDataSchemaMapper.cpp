/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/thread/encryptors/message/MessageDataSchemaMapper.hpp"

#include "privmx/endpoint/thread/ThreadException.hpp"
#include <Poco/JSON/Object.h>
#include <privmx/endpoint/core/encryptors/DataSchemaMapperUtils.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::thread;

MessageDataSchemaMapper::MessageDataSchemaMapper(
    const privmx::crypto::PrivateKey& userPrivKey,
    const core::Connection& connection
)
    : _userPrivKey(userPrivKey), _connection(connection) {
    _strategyV4 = std::make_shared<MessageDataSchemaStrategyV4>();
    _strategyMapper.registerStrategy(MessageDataSchema::Version::VERSION_4, _strategyV4);
    _strategyV5 = std::make_shared<MessageDataSchemaStrategyV5>();
    _strategyMapper.registerStrategy(MessageDataSchema::Version::VERSION_5, _strategyV5);
}

Poco::Dynamic::Var MessageDataSchemaMapper::encrypt(
    const std::string& threadId,
    const std::string& resourceId,
    const std::string& contextId,
    const std::string& moduleResourceId,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const core::Buffer& data,
    const core::DecryptedEncKeyV2& msgKey
) {
    switch (msgKey.dataStructureVersion) {
    case core::EncryptionKeyDataSchema::Version::UNKNOWN:
        throw UnknowThreadFormatException();
    case core::EncryptionKeyDataSchema::Version::VERSION_1: {
        return _strategyV4->encrypt(publicMeta, privateMeta, data, _userPrivKey, msgKey.key).toJSON();
    }
    case core::EncryptionKeyDataSchema::Version::VERSION_2: {
        auto messageDIO = _connection.getImpl()->createDIO(contextId, resourceId, threadId, moduleResourceId);
        return _strategyV5->encrypt(publicMeta, privateMeta, data, _userPrivKey, msgKey.key, messageDIO).toJSON();
    }
    }
    throw UnknowThreadFormatException();
}

std::tuple<Message, core::DataIntegrityObject> MessageDataSchemaMapper::decrypt(
    const server::Message& message,
    const core::DecryptedEncKey& encKey
) {
    return _strategyMapper.dispatch(
        static_cast<int64_t>(getMessagesDataStructureVersion(message)), message, encKey,
        [&]() -> std::tuple<Message, core::DataIntegrityObject> {
            return {
                toLibMessage(
                    message, {}, {}, {}, {}, UnknowMessageFormatException().getCode(),
                    MessageDataSchema::Version::UNKNOWN
                ),
                {}
            };
        }
    );
}

MessageDataSchema::Version MessageDataSchemaMapper::getMessagesDataStructureVersion(const server::Message& message) {
    return core::DataSchemaMapperUtils::mapVersionedData(
        message.data, MessageDataSchema::Version::UNKNOWN,
        [](int64_t v) {
            switch (v) {
            case MessageDataSchema::Version::VERSION_4:
                return MessageDataSchema::Version::VERSION_4;
            case MessageDataSchema::Version::VERSION_5:
                return MessageDataSchema::Version::VERSION_5;
            default:
                return MessageDataSchema::Version::UNKNOWN;
            }
        }
    );
}

uint32_t MessageDataSchemaMapper::validateMessageDataIntegrity(
    const server::Message& message,
    const std::string& threadResourceId
) {
    return core::DataSchemaMapperUtils::toStatusCode([&] {
        switch (getMessagesDataStructureVersion(message)) {
        case MessageDataSchema::Version::VERSION_4:
            return;
        case MessageDataSchema::Version::VERSION_5: {
            auto encData = server::EncryptedMessageDataV5::fromJSON(message.data);
            auto dio = _strategyV5->getDIOAndAssertIntegrity(encData);
            const auto& lastModifier = message.updates.empty() ? message.author : message.updates.back().author;
            const auto lastDate = message.updates.empty() ? message.createDate : message.updates.back().createDate;
            core::DataSchemaMapperUtils::assertEntryDIOIntegrity(
                dio, message.contextId, message.resourceId, message.threadId, threadResourceId, lastModifier, lastDate,
                [] { throw MessageDataIntegrityException(); }
            );
            return;
        }
        default:
            throw UnknowMessageFormatException();
        }
    });
}

ThreadDataSchema::Version MessageDataSchemaMapper::getMinimumContainerSchemaVersionForMessage(
    const server::Message& message
) {
    switch (getMessagesDataStructureVersion(message)) {
    case MessageDataSchema::Version::VERSION_4:
        return ThreadDataSchema::VERSION_4;
    case MessageDataSchema::Version::VERSION_5:
        return ThreadDataSchema::VERSION_5;
    default:
        return ThreadDataSchema::UNKNOWN;
    }
}

Message MessageDataSchemaMapper::toLibMessage(
    const server::Message& message,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const core::Buffer& data,
    const std::string& authorPubKey,
    int64_t statusCode,
    int64_t schemaVersion
) {
    return Message{
        .info =
            {.threadId = message.threadId,
             .messageId = message.id,
             .createDate = message.createDate,
             .author = message.author},
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .data = data,
        .authorPubKey = authorPubKey,
        .statusCode = statusCode,
        .schemaVersion = schemaVersion
    };
}

std::vector<Message> MessageDataSchemaMapper::validateDecryptAndConvertMessages(
    const std::vector<server::Message>& messages,
    const core::ModuleKeys& threadKeys,
    const std::shared_ptr<core::KeyProvider>& keyProvider,
    const core::KeyProvider::GroupPrivKeyResolver& groupPrivKeyResolver
) {
    return core::DataSchemaMapperUtils::batchValidateDecryptVerifyEntries<Message>(
        messages, threadKeys, keyProvider, _connection,
        [&](const server::Message& msg) { return validateMessageDataIntegrity(msg, threadKeys.moduleResourceId); },
        [&](const server::Message& msg) {
            return core::DataSchemaMapperUtils::toStatusCode([&] {
                _messageKeyIdFormatValidator.assertKeyIdFormat(msg.keyId);
            });
        },
        [&](const server::Message& msg, const core::DecryptedEncKey& key) { return decrypt(msg, key); },
        [](const server::Message& msg, uint32_t code) {
            return toLibMessage(msg, {}, {}, {}, {}, code, MessageDataSchema::Version::UNKNOWN);
        },
        groupPrivKeyResolver
    );
}

Message MessageDataSchemaMapper::validateDecryptAndConvertMessage(
    const server::Message& message,
    const core::ModuleKeys& threadKeys,
    const std::shared_ptr<core::KeyProvider>& keyProvider,
    const core::KeyProvider::GroupPrivKeyResolver& groupPrivKeyResolver
) {
    return validateDecryptAndConvertMessages({message}, threadKeys, keyProvider, groupPrivKeyResolver)[0];
}
