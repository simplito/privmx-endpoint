/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/inbox/encryptors/inbox/InboxDataSchemaMapper.hpp"

#include <Poco/JSON/Object.h>
#include <privmx/endpoint/core/Factory.hpp>
#include <privmx/endpoint/core/encryptors/DataSchemaMapperUtils.hpp>

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

server::InboxData InboxDataSchemaMapper::encrypt(const InboxDataProcessorModelV5& data, const std::string& key) {
    return _strategyV5->packForServer(data, _userPrivKey, key);
}

std::tuple<Inbox, core::DataIntegrityObject> InboxDataSchemaMapper::decrypt(
    const server::InboxInfo& inbox,
    const core::DecryptedEncKey& encKey
) {
    return _strategyMapper.dispatch(
        static_cast<int64_t>(getDataStructureVersion(inbox.data.back())), inbox, encKey,
        [&]() -> std::tuple<Inbox, core::DataIntegrityObject> {
            return {
                toLibInbox(
                    inbox, {}, {}, {}, UnknownInboxFormatException().getCode(), InboxDataSchema::Version::UNKNOWN
                ),
                {}
            };
        }
    );
}

InboxDataSchema::Version InboxDataSchemaMapper::getDataStructureVersion(const server::InboxDataEntry& entry) {
    return core::DataSchemaMapperUtils::mapVersionedData(
        entry.data.meta, InboxDataSchema::Version::UNKNOWN,
        [](int64_t v) {
            switch (v) {
            case InboxDataSchema::Version::VERSION_4:
                return InboxDataSchema::Version::VERSION_4;
            case InboxDataSchema::Version::VERSION_5:
                return InboxDataSchema::Version::VERSION_5;
            default:
                return InboxDataSchema::Version::UNKNOWN;
            }
        }
    );
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
        core::DataSchemaMapperUtils::assertContainerDIOIntegrity(dio, inbox, [] {
            throw InboxDataIntegrityException();
        });
        return;
    }
    default:
        throw UnknownInboxFormatException();
    }
}

uint32_t InboxDataSchemaMapper::validateDataIntegrity(const server::InboxInfo& inbox) {
    return core::DataSchemaMapperUtils::toStatusCode([&] { assertDataIntegrity(inbox); });
}

InboxPublicViewData InboxDataSchemaMapper::getPublicViewData(const server::InboxGetPublicViewResult& publicView) {
    InboxPublicViewData result;
    if (publicView.publicData.type() == typeid(Poco::JSON::Object::Ptr)) {
        auto versioned = core::dynamic::VersionedData::fromJSON(publicView.publicData);
        switch (versioned.version) {
        case InboxDataSchema::Version::VERSION_4:
            return _strategyV4->getPublicViewData(publicView);
        case InboxDataSchema::Version::VERSION_5:
            return _strategyV5->getPublicViewData(publicView);
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
    default:
        throw UnknownInboxFormatException();
    }
}

std::vector<Inbox> InboxDataSchemaMapper::validateDecryptAndConvertInboxes(
    const std::vector<server::InboxInfo>& inboxes,
    const std::shared_ptr<core::KeyProvider>& keyProvider
) {
    return core::DataSchemaMapperUtils::batchValidateDecryptVerifyContainers<Inbox>(
        inboxes, keyProvider, _connection, [&](const server::InboxInfo& inbox) { return validateDataIntegrity(inbox); },
        [](const server::InboxInfo& inbox) -> core::EncKeyLocation {
            return {.contextId = inbox.contextId, .resourceId = inbox.resourceId.value_or("")};
        },
        [&](const server::InboxInfo& inbox, const core::DecryptedEncKey& key) { return decrypt(inbox, key); },
        [](const server::InboxInfo& inbox, uint32_t code) {
            return toLibInbox(inbox, {}, {}, {}, code, InboxDataSchema::Version::UNKNOWN);
        }
    );
}

Inbox InboxDataSchemaMapper::validateDecryptAndConvertInbox(
    const server::InboxInfo& inbox,
    const std::shared_ptr<core::KeyProvider>& keyProvider
) {
    return validateDecryptAndConvertInboxes({inbox}, keyProvider)[0];
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
