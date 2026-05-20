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
#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/CoreConstants.hpp>
#include <privmx/endpoint/core/DynamicTypes.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/endpoint/core/TimestampValidator.hpp>
#include <set>

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
    auto version = getMessagesDataStructureVersion(message);
    auto strategy = _strategyMapper.getStrategy(static_cast<int64_t>(version));
    if (!strategy) {
        auto e = UnknowMessageFormatException();
        return {
            toLibMessage(message, {}, {}, {}, {}, e.getCode(), MessageDataSchema::Version::UNKNOWN),
            core::DataIntegrityObject{}
        };
    }
    return strategy->decryptAndConvert(message, encKey);
}

MessageDataSchema::Version MessageDataSchemaMapper::getMessagesDataStructureVersion(const server::Message& message) {
    if (message.data.type() == typeid(Poco::JSON::Object::Ptr)) {
        auto versioned = core::dynamic::VersionedData::fromJSON(message.data);
        switch (versioned.version) {
        case MessageDataSchema::Version::VERSION_4:
            return MessageDataSchema::Version::VERSION_4;
        case MessageDataSchema::Version::VERSION_5:
            return MessageDataSchema::Version::VERSION_5;
        default:
            return MessageDataSchema::Version::UNKNOWN;
        }
    }
    return MessageDataSchema::Version::UNKNOWN;
}

uint32_t MessageDataSchemaMapper::validateMessageDataIntegrity(
    const server::Message& message,
    const std::string& threadResourceId
) {
    try {
        switch (getMessagesDataStructureVersion(message)) {
        case MessageDataSchema::Version::VERSION_4:
            return 0;
        case MessageDataSchema::Version::VERSION_5: {
            auto encData = server::EncryptedMessageDataV5::fromJSON(message.data);
            auto dio = _strategyV5->getDIOAndAssertIntegrity(encData);
            if (dio.contextId != message.contextId ||
                dio.resourceId != message.resourceId ||
                !dio.containerId.has_value() ||
                dio.containerId.value() != message.threadId ||
                !dio.containerResourceId.has_value() ||
                dio.containerResourceId.value() != threadResourceId ||
                dio.creatorUserId != (message.updates.empty() ? message.author : message.updates.back().author) ||
                !core::TimestampValidator::validate(
                    dio.timestamp, (message.updates.empty() ? message.createDate : message.updates.back().createDate)
                )) {
                return MessageDataIntegrityException().getCode();
            }
            return 0;
        }
        default:
            return UnknowMessageFormatException().getCode();
        }
    } catch (const core::Exception& e) { return e.getCode(); } catch (const privmx::utils::PrivmxException& e) {
        return core::ExceptionConverter::convert(e).getCode();
    } catch (...) { return ENDPOINT_CORE_EXCEPTION_CODE; }
    return UnknowMessageFormatException().getCode();
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
    return ThreadDataSchema::UNKNOWN;
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
    std::vector<server::Message> messages,
    const core::ModuleKeys& threadKeys,
    const std::shared_ptr<core::KeyProvider>& keyProvider
) {
    if (messages.size() == 0) {
        return std::vector<Message>{};
    }
    std::vector<Message> result(messages.size());
    std::vector<core::DataIntegrityObject> messagesDIO(messages.size());
    std::set<std::string> seenRandomIds;

    // integrity validation
    for (size_t i = 0; i < messages.size(); i++) {
        auto code = validateMessageDataIntegrity(messages[i], threadKeys.moduleResourceId);
        if (code != 0) {
            result[i] = toLibMessage(messages[i], {}, {}, {}, {}, code, MessageDataSchema::Version::UNKNOWN);
        }
    }

    // single batch key fetch
    const core::EncKeyLocation location{.contextId = threadKeys.contextId, .resourceId = threadKeys.moduleResourceId};
    core::KeyDecryptionAndVerificationRequest keyRequest;
    for (size_t i = 0; i < messages.size(); i++) {
        if (result[i].statusCode != 0) {
            continue;
        }
        try {
            _messageKeyIdFormatValidator.assertKeyIdFormat(messages[i].keyId);
        } catch (const core::Exception& e) {
            result[i] = toLibMessage(messages[i], {}, {}, {}, {}, e.getCode(), MessageDataSchema::Version::UNKNOWN);
            continue;
        }
        keyRequest.addOne(threadKeys.keys, messages[i].keyId, location);
    }
    auto keysResult = keyProvider->getKeysAndVerify(keyRequest);
    auto keyMapIt = keysResult.find(location);

    // decrypt, deduplication check
    for (size_t i = 0; i < messages.size(); i++) {
        if (result[i].statusCode != 0) {
            continue;
        }
        try {
            auto [decryptedMessage, dio] = decrypt(messages[i], keyMapIt->second.at(messages[i].keyId));
            result[i] = decryptedMessage;
            messagesDIO[i] = dio;
            if (!seenRandomIds.insert(dio.randomId + "-" + std::to_string(dio.timestamp)).second) {
                result[i].statusCode = core::DataIntegrityObjectDuplicatedException().getCode();
            }
        } catch (const core::Exception& e) {
            result[i] = toLibMessage(messages[i], {}, {}, {}, {}, e.getCode(), MessageDataSchema::Version::UNKNOWN);
        }
    }

    // single batch identity verification
    std::vector<core::VerificationRequest> verifyRequests;
    std::vector<size_t> verifyIndices;
    for (size_t i = 0; i < result.size(); i++) {
        if (result[i].statusCode != 0) {
            continue;
        }
        verifyRequests.push_back(
            {.contextId = threadKeys.contextId,
             .senderId = result[i].info.author,
             .senderPubKey = result[i].authorPubKey,
             .date = result[i].info.createDate,
             .bridgeIdentity = messagesDIO[i].bridgeIdentity}
        );
        verifyIndices.push_back(i);
    }
    auto verified = _connection.getImpl()->getUserVerifier()->verify(verifyRequests);
    for (size_t j = 0; j < verifyIndices.size(); j++)
        result[verifyIndices[j]].statusCode = verified[j] ?
            0 :
            core::ExceptionConverter::getCodeOfUserVerificationFailureException();
    return result;
}

Message MessageDataSchemaMapper::validateDecryptAndConvertMessage(
    server::Message message,
    const core::ModuleKeys& threadKeys,
    const std::shared_ptr<core::KeyProvider>& keyProvider
) {
    return validateDecryptAndConvertMessages({std::move(message)}, threadKeys, keyProvider)[0];
}
