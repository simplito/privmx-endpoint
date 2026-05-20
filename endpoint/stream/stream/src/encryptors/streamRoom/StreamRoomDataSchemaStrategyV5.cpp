/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/stream/encryptors/streamRoom/StreamRoomDataSchemaStrategyV5.hpp"

#include <privmx/endpoint/core/Factory.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::stream;

core::DecryptedModuleDataV5 StreamRoomDataSchemaStrategyV5::decrypt(
    const server::StreamRoomInfo& streamRoom,
    const core::DecryptedEncKey& encKey
) const {
    auto encryptedData = core::dynamic::EncryptedModuleDataV5::fromJSON(streamRoom.data.back().data);
    core::DecryptedModuleDataV5 result;
    if (encKey.statusCode != 0) {
        result = _encryptor.extractPublic(encryptedData);
        result.statusCode = encKey.statusCode;
    } else {
        result = _encryptor.decrypt(encryptedData, encKey.key);
    }
    return result;
}

std::tuple<StreamRoom, core::DataIntegrityObject> StreamRoomDataSchemaStrategyV5::convert(
    const server::StreamRoomInfo& streamRoom,
    const core::DecryptedModuleDataV5& raw
) const {
    return {
        toLibStreamRoom(streamRoom, raw.publicMeta, raw.privateMeta, raw.statusCode, StreamRoomDataSchema::Version::VERSION_5),
        raw.dio
    };
}

std::tuple<StreamRoom, core::DataIntegrityObject> StreamRoomDataSchemaStrategyV5::makeErrorResult(
    const server::StreamRoomInfo& streamRoom,
    int64_t errorCode
) const {
    return {
        toLibStreamRoom(streamRoom, {}, {}, errorCode, StreamRoomDataSchema::Version::VERSION_5),
        core::DataIntegrityObject{}
    };
}

core::DataIntegrityObject StreamRoomDataSchemaStrategyV5::getDIOAndAssertIntegrity(
    const core::dynamic::EncryptedModuleDataV5& encData
) const {
    return _encryptor.getDIOAndAssertIntegrity(encData);
}

StreamRoom StreamRoomDataSchemaStrategyV5::toLibStreamRoom(
    const server::StreamRoomInfo& info,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    int64_t statusCode,
    int64_t schemaVersion
) {
    return StreamRoom{
        .contextId = info.contextId,
        .streamRoomId = info.id,
        .createDate = info.createDate,
        .creator = info.creator,
        .lastModificationDate = info.lastModificationDate,
        .lastModifier = info.lastModifier,
        .users = info.users,
        .managers = info.managers,
        .version = info.version,
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .policy = core::Factory::parsePolicyServerObject(info.policy),
        .statusCode = statusCode,
        .schemaVersion = schemaVersion,
        .closed = info.closed.value_or(true)
    };
}
