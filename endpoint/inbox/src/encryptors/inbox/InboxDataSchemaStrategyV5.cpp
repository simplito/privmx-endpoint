/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/inbox/encryptors/inbox/InboxDataSchemaStrategyV5.hpp"

#include <privmx/endpoint/core/CoreConstants.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/endpoint/core/Factory.hpp>

#include "privmx/endpoint/inbox/Constants.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::inbox;

InboxDataResultV5 InboxDataSchemaStrategyV5::decrypt(
    const server::InboxInfo& inbox,
    const core::DecryptedEncKey& encKey
) const {
    return _processor.unpackAll(inbox.data.back().data, encKey.key);
}

std::tuple<Inbox, core::DataIntegrityObject> InboxDataSchemaStrategyV5::convert(
    const server::InboxInfo& inbox,
    const InboxDataResultV5& raw
) const {
    return {
        Inbox{
            .inboxId = inbox.id,
            .contextId = inbox.contextId,
            .createDate = inbox.createDate,
            .creator = inbox.creator,
            .lastModificationDate = inbox.lastModificationDate,
            .lastModifier = inbox.lastModifier,
            .users = inbox.users,
            .managers = inbox.managers,
            .version = inbox.version,
            .publicMeta = raw.publicData.publicMeta,
            .privateMeta = raw.privateData.privateMeta,
            .filesConfig = raw.filesConfig,
            .policy = core::Factory::parsePolicyServerObject(inbox.policy),
            .statusCode = raw.statusCode,
            .schemaVersion = InboxDataSchema::Version::VERSION_5
        },
        raw.privateData.dio
    };
}

std::tuple<Inbox, core::DataIntegrityObject> InboxDataSchemaStrategyV5::makeErrorResult(
    const server::InboxInfo& inbox,
    int64_t errorCode
) const {
    return {
        Inbox{
            .inboxId = inbox.id,
            .contextId = inbox.contextId,
            .createDate = inbox.createDate,
            .creator = inbox.creator,
            .lastModificationDate = inbox.lastModificationDate,
            .lastModifier = inbox.lastModifier,
            .users = inbox.users,
            .managers = inbox.managers,
            .version = inbox.version,
            .publicMeta = {},
            .privateMeta = {},
            .filesConfig = {},
            .policy = core::Factory::parsePolicyServerObject(inbox.policy),
            .statusCode = errorCode,
            .schemaVersion = InboxDataSchema::Version::VERSION_5
        },
        core::DataIntegrityObject{}
    };
}

InboxPublicDataV5AsResult InboxDataSchemaStrategyV5::unpackPublicOnly(const Poco::Dynamic::Var& publicData) const {
    return _processor.unpackPublicOnly(publicData);
}

InboxInternalMetaV5 InboxDataSchemaStrategyV5::decryptInternalMeta(
    const server::InboxDataEntry& entry,
    const core::DecryptedEncKey& encKey
) const {
    return _processor.unpackAll(entry.data, encKey.key).privateData.internalMeta;
}

core::DataIntegrityObject InboxDataSchemaStrategyV5::getDIOAndAssertIntegrity(
    const server::InboxData& data
) const {
    return _processor.getDIOAndAssertIntegrity(data);
}

server::InboxData InboxDataSchemaStrategyV5::packForServer(
    const InboxDataProcessorModelV5& data,
    const privmx::crypto::PrivateKey& authorPrivateKey,
    const std::string& inboxKey
) const {
    return _processor.packForServer(data, authorPrivateKey, inboxKey);
}
