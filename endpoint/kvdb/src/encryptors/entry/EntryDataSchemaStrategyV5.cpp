/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/kvdb/encryptors/entry/EntryDataSchemaStrategyV5.hpp"
#include "privmx/endpoint/kvdb/encryptors/entry/EntryDataSchemaMapper.hpp"

#include "privmx/endpoint/kvdb/Constants.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::kvdb;

server::EncryptedKvdbEntryDataV5 EntryDataSchemaStrategyV5::getEncryptedData(const server::KvdbEntryInfo& model) const {
    return server::EncryptedKvdbEntryDataV5::fromJSON(model.kvdbEntryValue);
}

std::tuple<KvdbEntry, core::DataIntegrityObject> EntryDataSchemaStrategyV5::convert(
    const server::KvdbEntryInfo& entry,
    const DecryptedKvdbEntryDataV5& raw
) const {
    return {
        EntryDataSchemaMapper::toLibKvdbEntry(
            entry, raw.publicMeta, raw.privateMeta, raw.data, raw.authorPubKey, raw.statusCode,
            KvdbEntryDataSchema::Version::VERSION_5
        ),
        raw.dio
    };
}

KvdbEntry EntryDataSchemaStrategyV5::toLibError(const server::KvdbEntryInfo& entry, int64_t errorCode) const {
    return EntryDataSchemaMapper::toLibKvdbEntry(
        entry, {}, {}, {}, {}, errorCode, KvdbEntryDataSchema::Version::VERSION_5
    );
}
