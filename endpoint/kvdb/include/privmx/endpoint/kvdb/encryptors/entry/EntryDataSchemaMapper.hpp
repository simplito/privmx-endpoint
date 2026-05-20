/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_KVDB_ENTRYDATASCHEMAMAPPER_HPP_
#define _PRIVMXLIB_ENDPOINT_KVDB_ENTRYDATASCHEMAMAPPER_HPP_

#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <tuple>
#include <vector>

#include <Poco/Dynamic/Var.h>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/KeyProvider.hpp>
#include <privmx/endpoint/core/TimestampValidator.hpp>
#include <privmx/endpoint/core/encryptors/VersionStrategyMapper.hpp>

#include "privmx/endpoint/kvdb/Constants.hpp"
#include "privmx/endpoint/kvdb/KvdbTypes.hpp"
#include "privmx/endpoint/kvdb/ServerTypes.hpp"
#include "privmx/endpoint/kvdb/Types.hpp"
#include "privmx/endpoint/kvdb/encryptors/entry/EntryDataEncryptorV5.hpp"
#include "privmx/endpoint/kvdb/encryptors/entry/EntryDataSchemaStrategyV5.hpp"

namespace privmx {
namespace endpoint {
namespace kvdb {

class EntryDataSchemaMapper {
public:
    EntryDataSchemaMapper(const privmx::crypto::PrivateKey& userPrivKey, const core::Connection& connection);

    Poco::Dynamic::Var encrypt(
        const std::string& kvdbId,
        const std::string& resourceId,
        const std::string& contextId,
        const std::string& moduleResourceId,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const core::Buffer& data,
        const core::DecryptedEncKeyV2& entryKey
    );

    std::tuple<KvdbEntry, core::DataIntegrityObject> decrypt(
        const server::KvdbEntryInfo& entry,
        const core::DecryptedEncKey& encKey
    );

    KvdbEntryDataSchema::Version getDataStructureVersion(const server::KvdbEntryInfo& entry);

    uint32_t validateEntryDataIntegrity(
        const server::KvdbEntryInfo& entry,
        const std::string& kvdbResourceId
    );

    KvdbEntry validateDecryptAndConvertEntryDataToEntry(
        server::KvdbEntryInfo entry,
        const core::ModuleKeys& kvdbKeys,
        const std::shared_ptr<core::KeyProvider>& keyProvider
    );

    std::vector<KvdbEntry> validateDecryptAndConvertKvdbEntriesDataToKvdbEntries(
        std::vector<server::KvdbEntryInfo> entries,
        const core::ModuleKeys& kvdbKeys,
        const std::shared_ptr<core::KeyProvider>& keyProvider
    );

private:
    privmx::crypto::PrivateKey _userPrivKey;
    core::Connection _connection;
    core::VersionStrategyMapper<server::KvdbEntryInfo, std::tuple<KvdbEntry, core::DataIntegrityObject>> _strategyMapper;
    std::shared_ptr<EntryDataSchemaStrategyV5> _strategyV5;
    EntryDataEncryptorV5 _encryptorV5;
};

} // namespace kvdb
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_KVDB_ENTRYDATAENCRYPTORMAPPER_HPP_
