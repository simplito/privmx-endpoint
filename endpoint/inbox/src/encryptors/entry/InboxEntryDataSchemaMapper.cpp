/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <vector>

#include <privmx/utils/Utils.hpp>

#include "privmx/endpoint/inbox/InboxException.hpp"
#include "privmx/endpoint/inbox/encryptors/entry/InboxEntryDataSchemaMapper.hpp"

using namespace privmx;
using namespace privmx::endpoint;
using namespace privmx::endpoint::inbox;

InboxEntryDataSchemaMapper::InboxEntryDataSchemaMapper(
    const std::shared_ptr<core::KeyProvider>& keyProvider,
    const std::shared_ptr<ServerApi>& serverApi,
    const store::StoreApi& storeApi
) : _keyProvider(keyProvider), _strategyV1(serverApi, storeApi) {}

inbox::server::InboxMessageServer InboxEntryDataSchemaMapper::unpackInboxOrigMessage(
    const std::string& serialized
) {
    try {
        auto json = utils::Base64::toString(serialized);
        return inbox::server::InboxMessageServer::deserialize(json);
    } catch (...) { throw FailedToExtractMessagePublicMetaException(); }
}

std::string InboxEntryDataSchemaMapper::encrypt(
    const InboxEntrySendModel& data,
    privmx::crypto::PrivateKey& userPriv,
    privmx::crypto::PublicKey& inboxPub
) {
    return _strategyV1.encrypt(data, userPriv, inboxPub);
}

InboxEntryDataResult InboxEntryDataSchemaMapper::decrypt(
    std::string& data,
    privmx::crypto::PrivateKey& inboxPriv
) {
    return _strategyV1.decrypt(data, inboxPriv);
}

InboxEntryPublicDataResult InboxEntryDataSchemaMapper::decryptPublicOnly(std::string& data) {
    return _strategyV1.decryptPublicOnly(data);
}

InboxEntryResult InboxEntryDataSchemaMapper::decryptInboxEntry(
    thread::server::Message message,
    const core::ModuleKeys& inboxKeys
) {
    return _strategyV1.decryptEntry(message, inboxKeys, _keyProvider);
}

inbox::InboxEntry InboxEntryDataSchemaMapper::convertInboxEntry(
    thread::server::Message message,
    const InboxEntryResult& inboxEntry
) {
    return _strategyV1.convertToFinal(message, inboxEntry, readInboxIdFromMessageKeyId(message.keyId));
}

inbox::InboxEntry InboxEntryDataSchemaMapper::decryptAndConvertInboxEntry(
    thread::server::Message message,
    const core::ModuleKeys& inboxKeys
) {
    auto inboxEntry = decryptInboxEntry(message, inboxKeys);
    return convertInboxEntry(message, inboxEntry);
}

std::string InboxEntryDataSchemaMapper::readInboxIdFromMessageKeyId(const std::string& keyId) {
    _messageKeyIdFormatValidator.assertKeyIdFormat(keyId);
    std::string trimmedKeyId = keyId.substr(1, keyId.size() - 2);
    std::vector<std::string> tmp = utils::Utils::split(trimmedKeyId, "-");
    return tmp[1];
}
