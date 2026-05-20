/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_KVDB_ENTRYDATASCHEMASTRATEGYV5_HPP_
#define _PRIVMXLIB_ENDPOINT_KVDB_ENTRYDATASCHEMASTRATEGYV5_HPP_

#include <tuple>

#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/encryptors/TypedDataSchemaStrategy.hpp>

#include "privmx/endpoint/kvdb/Constants.hpp"
#include "privmx/endpoint/kvdb/KvdbTypes.hpp"
#include "privmx/endpoint/kvdb/ServerTypes.hpp"
#include "privmx/endpoint/kvdb/Types.hpp"
#include "privmx/endpoint/kvdb/encryptors/entry/EntryDataEncryptorV5.hpp"

namespace privmx {
namespace endpoint {
namespace kvdb {

// clang-format off
class EntryDataSchemaStrategyV5 : public core::TypedDataSchemaStrategy<
    server::KvdbEntryInfo,
    DecryptedKvdbEntryDataV5,
    std::tuple<KvdbEntry, core::DataIntegrityObject>
> {
    // clang-format on
public:
    DecryptedKvdbEntryDataV5 decrypt(
        const server::KvdbEntryInfo& entry,
        const core::DecryptedEncKey& encKey
    ) const override;
    std::tuple<KvdbEntry, core::DataIntegrityObject> convert(
        const server::KvdbEntryInfo& entry,
        const DecryptedKvdbEntryDataV5& raw
    ) const override;
    std::tuple<KvdbEntry, core::DataIntegrityObject> makeErrorResult(
        const server::KvdbEntryInfo& entry,
        int64_t errorCode
    ) const override;
    core::DataIntegrityObject getDIOAndAssertIntegrity(const server::EncryptedKvdbEntryDataV5& encData) const;

    static KvdbEntry toLibKvdbEntry(
        const server::KvdbEntryInfo& entry,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const core::Buffer& data,
        const std::string& authorPubKey,
        int64_t statusCode,
        int64_t schemaVersion
    );

private:
    mutable EntryDataEncryptorV5 _encryptor;
};

} // namespace kvdb
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_KVDB_ENTRYDATASCHEMASTRATEGYV5_HPP_
