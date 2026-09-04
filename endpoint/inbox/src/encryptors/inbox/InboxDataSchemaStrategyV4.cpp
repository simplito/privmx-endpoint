/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/inbox/encryptors/inbox/InboxDataSchemaStrategyV4.hpp"
#include "privmx/endpoint/inbox/encryptors/inbox/InboxDataSchemaMapper.hpp"

#include <privmx/endpoint/core/CoreConstants.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/endpoint/core/Factory.hpp>

#include "privmx/endpoint/inbox/Constants.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::inbox;

InboxDataResultV4 InboxDataSchemaStrategyV4::decrypt(
    const server::InboxInfo& inbox,
    const core::DecryptedEncKey& encKey
) const {
    return _processor.unpackAll(inbox.data.back().data, encKey.key);
}

std::tuple<Inbox, core::DataIntegrityObject> InboxDataSchemaStrategyV4::convert(
    const server::InboxInfo& inbox,
    const InboxDataResultV4& raw
) const {
    return {
        InboxDataSchemaMapper::toLibInbox(
            inbox, raw.publicData.publicMeta, raw.privateData.privateMeta, raw.filesConfig, raw.statusCode,
            InboxDataSchema::Version::VERSION_4
        ),
        core::DataIntegrityObject{
            .creatorUserId = inbox.lastModifier,
            .creatorPubKey = raw.privateData.authorPubKey,
            .contextId = inbox.contextId,
            .resourceId = inbox.resourceId.value_or(""),
            .timestamp = inbox.lastModificationDate,
            .randomId = std::string(),
            .containerId = std::nullopt,
            .containerResourceId = std::nullopt,
            .bridgeIdentity = std::nullopt
        }
    };
}

InboxPublicDataV4AsResult InboxDataSchemaStrategyV4::unpackPublicOnly(const Poco::Dynamic::Var& publicData) const {
    return _processor.unpackPublicOnly(publicData);
}

InboxPublicViewData InboxDataSchemaStrategyV4::getPublicViewData(
    const server::InboxGetPublicViewResult& publicView
) const {
    auto publicData = unpackPublicOnly(publicView.publicData);
    InboxPublicViewData result;
    result.authorPubKey = publicData.authorPubKey;
    result.publicMeta = publicData.publicMeta;
    result.inboxEntriesPubKeyBase58DER = publicData.inboxEntriesPubKeyBase58DER;
    result.inboxEntriesKeyId = publicData.inboxEntriesKeyId;
    result.inboxId = publicView.inboxId;
    result.resourceId = "";
    result.version = publicView.version;
    result.dataStructureVersion = publicData.dataStructureVersion;
    result.statusCode = publicData.statusCode;
    return result;
}

InboxInternalMetaV5 InboxDataSchemaStrategyV4::decryptInternalMeta(
    const server::InboxDataEntry& /*entry*/,
    const core::DecryptedEncKey& /*encKey*/
) const {
    return InboxInternalMetaV5();
}

std::tuple<Inbox, core::DataIntegrityObject> InboxDataSchemaStrategyV4::makeErrorResult(
    const server::InboxInfo& inbox,
    int64_t errorCode
) const {
    return {
        InboxDataSchemaMapper::toLibInbox(inbox, {}, {}, {}, errorCode, InboxDataSchema::Version::VERSION_4),
        core::DataIntegrityObject{}
    };
}
