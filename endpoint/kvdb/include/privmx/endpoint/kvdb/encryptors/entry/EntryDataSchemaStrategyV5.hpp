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
#include <privmx/endpoint/core/encryptors/TypedDataSchemaStrategyV5.hpp>

#include "privmx/endpoint/kvdb/Constants.hpp"
#include "privmx/endpoint/kvdb/KvdbTypes.hpp"
#include "privmx/endpoint/kvdb/ServerTypes.hpp"
#include "privmx/endpoint/kvdb/Types.hpp"
#include "privmx/endpoint/kvdb/encryptors/entry/EntryDataEncryptorV5.hpp"

namespace privmx {
namespace endpoint {
namespace kvdb {

// clang-format off
class EntryDataSchemaStrategyV5 : public core::TypedDataSchemaStrategyV5<
    EntryDataEncryptorV5,
    server::EncryptedKvdbEntryDataV5,
    DecryptedKvdbEntryDataV5,
    server::KvdbEntryInfo,
    KvdbEntry
> {
    // clang-format on
public:
    std::tuple<KvdbEntry, core::DataIntegrityObject> convert(
        const server::KvdbEntryInfo& entry,
        const DecryptedKvdbEntryDataV5& raw
    ) const override;
    KvdbEntry toLibError(const server::KvdbEntryInfo& entry, int64_t errorCode) const override;

protected:
    server::EncryptedKvdbEntryDataV5 getEncryptedData(const server::KvdbEntryInfo& model) const override;
};

} // namespace kvdb
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_KVDB_ENTRYDATASCHEMASTRATEGYV5_HPP_
