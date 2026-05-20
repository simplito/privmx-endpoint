/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_INBOX_INBOXENTRYDATASCHEMASTRATEGYV1_HPP_
#define _PRIVMXLIB_ENDPOINT_INBOX_INBOXENTRYDATASCHEMASTRATEGYV1_HPP_

#include <memory>

#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/crypto/ecc/PublicKey.hpp>
#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/KeyProvider.hpp>
#include <privmx/endpoint/store/StoreApi.hpp>
#include <privmx/endpoint/thread/ServerTypes.hpp>

#include "privmx/endpoint/inbox/Constants.hpp"
#include "privmx/endpoint/inbox/InboxTypes.hpp"
#include "privmx/endpoint/inbox/ServerApi.hpp"
#include "privmx/endpoint/inbox/ServerTypes.hpp"
#include "privmx/endpoint/inbox/Types.hpp"
#include "privmx/endpoint/inbox/encryptors/entry/InboxEntryDataEncryptorV1.hpp"

namespace privmx {
namespace endpoint {
namespace inbox {

class InboxEntryDataSchemaStrategyV1 {
public:
    InboxEntryDataSchemaStrategyV1(const std::shared_ptr<ServerApi>& serverApi, const store::StoreApi& storeApi);
    std::string encrypt(
        const InboxEntrySendModel& data,
        privmx::crypto::PrivateKey& userPriv,
        privmx::crypto::PublicKey& inboxPub
    ) const;
    InboxEntryDataResult decrypt(std::string& data, privmx::crypto::PrivateKey& inboxPriv) const;
    InboxEntryPublicDataResult decryptPublicOnly(std::string& data) const;
    InboxEntryResult decryptEntry(
        const thread::server::Message& message,
        const core::ModuleKeys& inboxKeys,
        const std::shared_ptr<core::KeyProvider>& keyProvider
    ) const;
    inbox::InboxEntry convertToFinal(
        const thread::server::Message& message,
        const InboxEntryResult& raw,
        const std::string& inboxId
    ) const;

private:
    static InboxEntryResult makeEmptyResultWithStatusCode(int64_t statusCode);
    std::shared_ptr<ServerApi> _serverApi;
    store::StoreApi _storeApi;
    mutable InboxEntryDataEncryptorV1 _encryptor;
};

} // namespace inbox
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_INBOX_INBOXENTRYDATASCHEMASTRATEGYV1_HPP_
