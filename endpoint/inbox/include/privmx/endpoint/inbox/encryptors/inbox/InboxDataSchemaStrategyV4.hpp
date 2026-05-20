/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_INBOX_INBOXDATASCHEMASTRATEGYV4_HPP_
#define _PRIVMXLIB_ENDPOINT_INBOX_INBOXDATASCHEMASTRATEGYV4_HPP_

#include <tuple>

#include <Poco/Dynamic/Var.h>
#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/encryptors/TypedDataSchemaStrategy.hpp>

#include "privmx/endpoint/inbox/ServerTypes.hpp"
#include "privmx/endpoint/inbox/Types.hpp"
#include "privmx/endpoint/inbox/InboxTypes.hpp"
#include "privmx/endpoint/inbox/encryptors/inbox/InboxDataProcessorV4.hpp"

namespace privmx {
namespace endpoint {
namespace inbox {

// clang-format off
class InboxDataSchemaStrategyV4 : public core::TypedDataSchemaStrategy<
    server::InboxInfo,
    InboxDataResultV4,
    std::tuple<Inbox, core::DataIntegrityObject>
> {
    // clang-format on
public:
    InboxDataResultV4 decrypt(
        const server::InboxInfo& inbox,
        const core::DecryptedEncKey& encKey
    ) const override;
    std::tuple<Inbox, core::DataIntegrityObject> convert(
        const server::InboxInfo& inbox,
        const InboxDataResultV4& raw
    ) const override;
    std::tuple<Inbox, core::DataIntegrityObject> makeErrorResult(
        const server::InboxInfo& inbox,
        int64_t errorCode
    ) const override;
    InboxPublicDataV4AsResult unpackPublicOnly(const Poco::Dynamic::Var& publicData) const;
    InboxInternalMetaV5 decryptInternalMeta(
        const server::InboxDataEntry& entry,
        const core::DecryptedEncKey& encKey
    ) const;

private:
    mutable InboxDataProcessorV4 _processor;
};

} // namespace inbox
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_INBOX_INBOXDATASCHEMASTRATEGYV4_HPP_
