/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_INBOX_INBOXENTRYDATASCHEMAMAPPER_HPP_
#define _PRIVMXLIB_ENDPOINT_INBOX_INBOXENTRYDATASCHEMAMAPPER_HPP_

#include <memory>
#include <string>

#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/crypto/ecc/PublicKey.hpp>
#include <privmx/endpoint/core/KeyProvider.hpp>
#include <privmx/endpoint/store/StoreApi.hpp>
#include <privmx/endpoint/thread/ServerTypes.hpp>

#include "privmx/endpoint/inbox/InboxTypes.hpp"
#include "privmx/endpoint/inbox/MessageKeyIdFormatValidator.hpp"
#include "privmx/endpoint/inbox/ServerApi.hpp"
#include "privmx/endpoint/inbox/ServerTypes.hpp"
#include "privmx/endpoint/inbox/Types.hpp"
#include "privmx/endpoint/inbox/encryptors/entry/InboxEntryDataSchemaStrategyV1.hpp"

namespace privmx {
namespace endpoint {
namespace inbox {

class InboxEntryDataSchemaMapper {
public:
    InboxEntryDataSchemaMapper(
        const std::shared_ptr<core::KeyProvider>& keyProvider,
        const std::shared_ptr<ServerApi>& serverApi,
        const store::StoreApi& storeApi
    );

    static inbox::server::InboxMessageServer unpackInboxOrigMessage(const std::string& serialized);

    std::string encrypt(
        const InboxEntrySendModel& data,
        privmx::crypto::PrivateKey& userPriv,
        privmx::crypto::PublicKey& inboxPub
    );
    InboxEntryDataResult decrypt(std::string& data, privmx::crypto::PrivateKey& inboxPriv);
    InboxEntryPublicDataResult decryptPublicOnly(std::string& data);

    InboxEntryResult decryptInboxEntry(thread::server::Message message, const core::ModuleKeys& inboxKeys);
    inbox::InboxEntry convertInboxEntry(thread::server::Message message, const InboxEntryResult& inboxEntry);
    inbox::InboxEntry decryptAndConvertInboxEntry(thread::server::Message message, const core::ModuleKeys& inboxKeys);

private:
    std::string readInboxIdFromMessageKeyId(const std::string& keyId);

    std::shared_ptr<core::KeyProvider> _keyProvider;
    MessageKeyIdFormatValidator _messageKeyIdFormatValidator;
    InboxEntryDataSchemaStrategyV1 _strategyV1;
};

} // namespace inbox
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_INBOX_INBOXENTRYDATASCHEMAMAPPER_HPP_
