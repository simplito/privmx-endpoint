/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/inbox/encryptors/inbox/InboxDataSchemaMapper.hpp"

#include <set>

#include <Poco/JSON/Object.h>
#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/CoreConstants.hpp>
#include <privmx/endpoint/core/DynamicTypes.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/endpoint/core/Factory.hpp>
#include <privmx/endpoint/core/TimestampValidator.hpp>

#include "privmx/endpoint/inbox/InboxException.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::inbox;

InboxDataSchemaMapper::InboxDataSchemaMapper(
    const privmx::crypto::PrivateKey& userPrivKey,
    const core::Connection& connection
)
    : _userPrivKey(userPrivKey), _connection(connection) {
    _strategyV4 = std::make_shared<InboxDataSchemaStrategyV4>();
    _strategyMapper.registerStrategy(InboxDataSchema::Version::VERSION_4, _strategyV4);
    _strategyV5 = std::make_shared<InboxDataSchemaStrategyV5>();
    _strategyMapper.registerStrategy(InboxDataSchema::Version::VERSION_5, _strategyV5);
}

server::InboxData InboxDataSchemaMapper::encrypt(
    const InboxDataProcessorModelV5& data,
    const std::string& key
) {
    return _strategyV5->packForServer(data, _userPrivKey, key);
}

std::tuple<Inbox, core::DataIntegrityObject> InboxDataSchemaMapper::decrypt(
    const server::InboxInfo& inbox,
    const core::DecryptedEncKey& encKey
) {
    auto version = getDataStructureVersion(inbox.data.back());
    auto strategy = _strategyMapper.getStrategy(static_cast<int64_t>(version));
    if (!strategy) {
        auto e = UnknownInboxFormatException();
        return {toLibInbox(inbox, {}, {}, {}, e.getCode(), InboxDataSchema::Version::UNKNOWN),
                core::DataIntegrityObject{}};
    }
    return strategy->decryptAndConvert(inbox, encKey);
}

InboxDataSchema::Version InboxDataSchemaMapper::getDataStructureVersion(
    const server::InboxDataEntry& entry
) {
    if (entry.data.meta.type() == typeid(Poco::JSON::Object::Ptr)) {
        auto versioned = core::dynamic::VersionedData::fromJSON(entry.data.meta);
        switch (versioned.version) {
        case InboxDataSchema::Version::VERSION_4:
            return InboxDataSchema::Version::VERSION_4;
        case InboxDataSchema::Version::VERSION_5:
            return InboxDataSchema::Version::VERSION_5;
        default:
            return InboxDataSchema::Version::UNKNOWN;
        }
    }
    return InboxDataSchema::Version::UNKNOWN;
}

void InboxDataSchemaMapper::assertDataIntegrity(const server::InboxInfo& inbox) {
    const auto& entry = inbox.data.back();
    switch (getDataStructureVersion(entry)) {
    case InboxDataSchema::Version::UNKNOWN:
        throw UnknownInboxFormatException();
    case InboxDataSchema::Version::VERSION_4:
        return;
    case InboxDataSchema::Version::VERSION_5: {
        auto dio = _strategyV5->getDIOAndAssertIntegrity(entry.data);
        if (dio.contextId != inbox.contextId ||
            dio.resourceId != inbox.resourceId ||
            dio.creatorUserId != inbox.lastModifier ||
            !core::TimestampValidator::validate(dio.timestamp, inbox.lastModificationDate)) {
            throw InboxDataIntegrityException();
        }
        return;
    }
    }
    throw UnknownInboxFormatException();
}

uint32_t InboxDataSchemaMapper::validateDataIntegrity(const server::InboxInfo& inbox) {
    try {
        assertDataIntegrity(inbox);
        return 0;
    } catch (const core::Exception& e) { return e.getCode(); } catch (const privmx::utils::PrivmxException& e) {
        return core::ExceptionConverter::convert(e).getCode();
    } catch (...) { return ENDPOINT_CORE_EXCEPTION_CODE; }
}

InboxPublicViewData InboxDataSchemaMapper::getPublicViewData(const server::InboxGetPublicViewResult& publicView) {
    InboxPublicViewData result;
    if (publicView.publicData.type() == typeid(Poco::JSON::Object::Ptr)) {
        auto versioned = core::dynamic::VersionedData::fromJSON(publicView.publicData);
        switch (versioned.version) {
        case InboxDataSchema::Version::VERSION_4: {
            auto publicData = _strategyV4->unpackPublicOnly(publicView.publicData);
            result.inboxId = publicView.inboxId;
            result.resourceId = "";
            result.version = publicView.version;
            result.dataStructureVersion = publicData.dataStructureVersion;
            result.authorPubKey = publicData.authorPubKey;
            result.inboxEntriesPubKeyBase58DER = publicData.inboxEntriesPubKeyBase58DER;
            result.inboxEntriesKeyId = publicData.inboxEntriesKeyId;
            result.publicMeta = publicData.publicMeta;
            result.statusCode = publicData.statusCode;
            return result;
        }
        case InboxDataSchema::Version::VERSION_5: {
            auto publicData = _strategyV5->unpackPublicOnly(publicView.publicData);
            result.inboxId = publicView.inboxId;
            result.resourceId = "";
            result.version = publicView.version;
            result.dataStructureVersion = publicData.dataStructureVersion;
            result.authorPubKey = publicData.authorPubKey;
            result.inboxEntriesPubKeyBase58DER = publicData.inboxEntriesPubKeyBase58DER;
            result.inboxEntriesKeyId = publicData.inboxEntriesKeyId;
            result.publicMeta = publicData.publicMeta;
            result.statusCode = publicData.statusCode;
            return result;
        }
        }
    }
    auto e = UnknownInboxFormatException();
    result.statusCode = e.getCode();
    return result;
}

InboxInternalMetaV5 InboxDataSchemaMapper::decryptInternalMeta(
    const server::InboxDataEntry& entry,
    const core::DecryptedEncKey& encKey
) {
    switch (getDataStructureVersion(entry)) {
    case InboxDataSchema::Version::UNKNOWN:
        throw UnknownInboxFormatException();
    case InboxDataSchema::Version::VERSION_4:
        return _strategyV4->decryptInternalMeta(entry, encKey);
    case InboxDataSchema::Version::VERSION_5:
        return _strategyV5->decryptInternalMeta(entry, encKey);
    }
    throw UnknownInboxFormatException();
}

std::vector<Inbox> InboxDataSchemaMapper::validateDecryptAndConvertInboxes(
    std::vector<server::InboxInfo> inboxes,
    const std::shared_ptr<core::KeyProvider>& keyProvider
) {
    if (inboxes.size() == 0) {
        return std::vector<Inbox>{};
    }
    std::vector<Inbox> result(inboxes.size());
    std::vector<core::DataIntegrityObject> inboxesDIO(inboxes.size());
    // integrity validation
    for (size_t i = 0; i < inboxes.size(); i++) {
        result[i].statusCode = validateDataIntegrity(inboxes[i]);
        if (result[i].statusCode != 0) {
            result[i] = toLibInbox(inboxes[i], {}, {}, {}, result[i].statusCode, InboxDataSchema::Version::UNKNOWN);
        } else {
            result[i].statusCode = 0;
        }
    }
    // batch key fetch
    core::KeyDecryptionAndVerificationRequest keyRequest;
    for (size_t i = 0; i < inboxes.size(); i++) {
        if (result[i].statusCode != 0) continue;
        auto& inbox = inboxes[i];
        core::EncKeyLocation location{.contextId = inbox.contextId, .resourceId = inbox.resourceId.value_or("")};
        keyRequest.addOne(inbox.keys, inbox.data.back().keyId, location);
    }
    auto inboxesKeys = keyProvider->getKeysAndVerify(keyRequest);
    std::set<std::string> seenRandomIds;
    // decrypt + deduplication
    for (size_t i = 0; i < inboxes.size(); i++) {
        if (result[i].statusCode != 0) continue;
        auto& inbox = inboxes[i];
        try {
            auto inboxKeysIt = inboxesKeys.find(
                core::EncKeyLocation{.contextId = inbox.contextId, .resourceId = inbox.resourceId.value_or("")}
            );
            if (inboxKeysIt == inboxesKeys.end()) {
                throw UnknownInboxFormatException();
            }
            auto [decryptedInbox, dio] = decrypt(inbox, inboxKeysIt->second.at(inbox.data.back().keyId));
            result[i] = decryptedInbox;
            inboxesDIO[i] = dio;
            if (!seenRandomIds.insert(dio.randomId + "-" + std::to_string(dio.timestamp)).second) {
                result[i].statusCode = core::DataIntegrityObjectDuplicatedException().getCode();
            }
        } catch (const core::Exception& e) {
            result[i] = toLibInbox(inbox, {}, {}, {}, e.getCode(), InboxDataSchema::Version::UNKNOWN);
        }
    }
    // batch identity verification
    std::vector<core::VerificationRequest> verifyRequests;
    std::vector<size_t> verifyIndices;
    for (size_t i = 0; i < result.size(); i++) {
        if (result[i].statusCode != 0) continue;
        verifyRequests.push_back({
            .contextId = result[i].contextId,
            .senderId = result[i].lastModifier,
            .senderPubKey = inboxesDIO[i].creatorPubKey,
            .date = result[i].lastModificationDate,
            .bridgeIdentity = inboxesDIO[i].bridgeIdentity
        });
        verifyIndices.push_back(i);
    }
    auto verified = _connection.getImpl()->getUserVerifier()->verify(verifyRequests);
    for (size_t j = 0; j < verifyIndices.size(); j++) {
        result[verifyIndices[j]].statusCode =
            verified[j] ? 0 : core::ExceptionConverter::getCodeOfUserVerificationFailureException();
    }
    return result;
}

Inbox InboxDataSchemaMapper::validateDecryptAndConvertInbox(
    server::InboxInfo inbox,
    const std::shared_ptr<core::KeyProvider>& keyProvider
) {
    return validateDecryptAndConvertInboxes({std::move(inbox)}, keyProvider)[0];
}

Inbox InboxDataSchemaMapper::toLibInbox(
    const server::InboxInfo& info,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const std::optional<FilesConfig>& filesConfig,
    int64_t statusCode,
    int64_t schemaVersion
) {
    return Inbox{
        .inboxId = info.id,
        .contextId = info.contextId,
        .createDate = info.createDate,
        .creator = info.creator,
        .lastModificationDate = info.lastModificationDate,
        .lastModifier = info.lastModifier,
        .users = info.users,
        .managers = info.managers,
        .version = info.version,
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .filesConfig = filesConfig,
        .policy = core::Factory::parsePolicyServerObject(info.policy),
        .statusCode = statusCode,
        .schemaVersion = schemaVersion
    };
}
