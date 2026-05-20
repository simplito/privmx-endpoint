/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_INBOX_INBOXDATASCHEMAMAPPER_HPP_
#define _PRIVMXLIB_ENDPOINT_INBOX_INBOXDATASCHEMAMAPPER_HPP_

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <vector>

#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/KeyProvider.hpp>
#include <privmx/endpoint/core/TimestampValidator.hpp>
#include <privmx/endpoint/core/encryptors/VersionStrategyMapper.hpp>

#include <Poco/Dynamic/Var.h>

#include "privmx/endpoint/inbox/Constants.hpp"
#include "privmx/endpoint/inbox/InboxTypes.hpp"
#include "privmx/endpoint/inbox/ServerTypes.hpp"
#include "privmx/endpoint/inbox/Types.hpp"
#include "privmx/endpoint/inbox/encryptors/inbox/InboxDataSchemaStrategyV4.hpp"
#include "privmx/endpoint/inbox/encryptors/inbox/InboxDataSchemaStrategyV5.hpp"

namespace privmx {
namespace endpoint {
namespace inbox {

class InboxDataSchemaMapper {
public:
    InboxDataSchemaMapper(const privmx::crypto::PrivateKey& userPrivKey, const core::Connection& connection);

    server::InboxData encrypt(const InboxDataProcessorModelV5& data, const std::string& key);

    std::tuple<Inbox, core::DataIntegrityObject> decrypt(
        const server::InboxInfo& inbox,
        const core::DecryptedEncKey& encKey
    );

    InboxDataSchema::Version getDataStructureVersion(const server::InboxDataEntry& entry);

    void assertDataIntegrity(const server::InboxInfo& inbox);

    uint32_t validateDataIntegrity(const server::InboxInfo& inbox);

    InboxPublicViewData getPublicViewData(const server::InboxGetPublicViewResult& publicView);
    InboxInternalMetaV5 decryptInternalMeta(
        const server::InboxDataEntry& entry,
        const core::DecryptedEncKey& encKey
    );

    std::vector<Inbox> validateDecryptAndConvertInboxes(
        std::vector<server::InboxInfo> inboxes,
        const std::shared_ptr<core::KeyProvider>& keyProvider
    );

    Inbox validateDecryptAndConvertInbox(
        server::InboxInfo inbox,
        const std::shared_ptr<core::KeyProvider>& keyProvider
    );

    static Inbox toLibInbox(
        const server::InboxInfo& info,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const std::optional<FilesConfig>& filesConfig,
        int64_t statusCode,
        int64_t schemaVersion
    );

private:
    privmx::crypto::PrivateKey _userPrivKey;
    core::Connection _connection;
    core::VersionStrategyMapper<server::InboxInfo, std::tuple<Inbox, core::DataIntegrityObject>> _strategyMapper;
    std::shared_ptr<InboxDataSchemaStrategyV4> _strategyV4;
    std::shared_ptr<InboxDataSchemaStrategyV5> _strategyV5;
};

} // namespace inbox
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_INBOX_INBOXDATASCHEMAMAPPER_HPP_
