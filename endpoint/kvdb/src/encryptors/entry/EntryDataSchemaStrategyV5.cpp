/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/kvdb/encryptors/entry/EntryDataSchemaStrategyV5.hpp"

#include "privmx/endpoint/kvdb/Constants.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::kvdb;

DecryptedKvdbEntryDataV5 EntryDataSchemaStrategyV5::decrypt(
    const server::KvdbEntryInfo& entry,
    const core::DecryptedEncKey& encKey
) const {
    auto encryptedEntryData = server::EncryptedKvdbEntryDataV5::fromJSON(entry.kvdbEntryValue);
    if (encKey.statusCode != 0) {
        auto tmp = _encryptor.extractPublic(encryptedEntryData);
        tmp.statusCode = encKey.statusCode;
        return tmp;
    }
    return _encryptor.decrypt(encryptedEntryData, encKey.key);
}

std::tuple<KvdbEntry, core::DataIntegrityObject> EntryDataSchemaStrategyV5::convert(
    const server::KvdbEntryInfo& entry,
    const DecryptedKvdbEntryDataV5& raw
) const {
    return {
        toLibKvdbEntry(
            entry, raw.publicMeta, raw.privateMeta, raw.data, raw.authorPubKey, raw.statusCode,
            KvdbEntryDataSchema::Version::VERSION_5
        ),
        raw.dio
    };
}

std::tuple<KvdbEntry, core::DataIntegrityObject> EntryDataSchemaStrategyV5::makeErrorResult(
    const server::KvdbEntryInfo& entry,
    int64_t errorCode
) const {
    return {
        toLibKvdbEntry(entry, {}, {}, {}, {}, errorCode, KvdbEntryDataSchema::Version::VERSION_5),
        core::DataIntegrityObject{}
    };
}

core::DataIntegrityObject EntryDataSchemaStrategyV5::getDIOAndAssertIntegrity(
    const server::EncryptedKvdbEntryDataV5& encData
) const {
    return _encryptor.getDIOAndAssertIntegrity(encData);
}

KvdbEntry EntryDataSchemaStrategyV5::toLibKvdbEntry(
    const server::KvdbEntryInfo& entry,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const core::Buffer& data,
    const std::string& authorPubKey,
    int64_t statusCode,
    int64_t schemaVersion
) {
    return KvdbEntry{
        .info =
            {
                .kvdbId = entry.kvdbId,
                .key = entry.kvdbEntryKey,
                .createDate = entry.createDate,
                .author = entry.author,
            },
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .data = data,
        .authorPubKey = authorPubKey,
        .version = entry.version,
        .statusCode = statusCode,
        .schemaVersion = schemaVersion
    };
}
