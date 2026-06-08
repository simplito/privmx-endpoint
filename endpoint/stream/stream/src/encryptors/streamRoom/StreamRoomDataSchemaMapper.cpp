/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/stream/encryptors/streamRoom/StreamRoomDataSchemaMapper.hpp"

#include <Poco/JSON/Object.h>
#include <privmx/endpoint/core/Factory.hpp>
#include <privmx/endpoint/core/encryptors/DataSchemaMapperUtils.hpp>

#include "privmx/endpoint/stream/StreamException.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::stream;

StreamRoomDataSchemaMapper::StreamRoomDataSchemaMapper(
    const privmx::crypto::PrivateKey& userPrivKey,
    const core::Connection& connection
)
    : core::BaseModuleDataSchemaMapper(userPrivKey, connection) {
    _strategyV5 = std::make_shared<StreamRoomDataSchemaStrategyV5>();
    _strategyMapper.registerStrategy(core::ModuleDataSchema::Version::VERSION_5, _strategyV5);
}

Poco::Dynamic::Var StreamRoomDataSchemaMapper::encrypt(
    const core::ModuleDataToEncryptV5& data,
    const std::string& key
) {
    return _encryptorV5.encrypt(data, _userPrivKey, key).toJSON();
}

std::tuple<StreamRoom, core::DataIntegrityObject> StreamRoomDataSchemaMapper::decrypt(
    const server::StreamRoomInfo& streamRoom,
    const core::DecryptedEncKey& encKey
) {
    return _strategyMapper.dispatch(
        static_cast<int64_t>(getDataStructureVersion(streamRoom.data.back())), streamRoom, encKey,
        [&]() -> std::tuple<StreamRoom, core::DataIntegrityObject> {
            return {
                toLibStreamRoom(
                    streamRoom, {}, {}, UnknowStreamRoomFormatException().getCode(),
                    StreamRoomDataSchema::Version::UNKNOWN
                ),
                {}
            };
        }
    );
}

void StreamRoomDataSchemaMapper::assertDataIntegrity(const server::StreamRoomInfo& streamRoom) {
    const auto& entry = streamRoom.data.back();
    switch (getDataStructureVersion(entry)) {
    case core::ModuleDataSchema::Version::UNKNOWN:
        throw UnknowStreamRoomFormatException();
    case core::ModuleDataSchema::Version::VERSION_5: {
        auto encData = core::dynamic::EncryptedModuleDataV5::fromJSON(entry.data);
        auto dio = _strategyV5->getDIOAndAssertIntegrity(encData);
        if (dio.contextId != streamRoom.contextId ||
            dio.resourceId != streamRoom.resourceId.value_or("") ||
            dio.creatorUserId != streamRoom.lastModifier ||
            !core::TimestampValidator::validate(dio.timestamp, streamRoom.lastModificationDate)) {
            throw StreamRoomDataIntegrityException();
        }
        return;
    }
    default:
        throw UnknowStreamRoomFormatException();
    }
}

uint32_t StreamRoomDataSchemaMapper::validateDataIntegrity(const server::StreamRoomInfo& streamRoom) {
    return core::DataSchemaMapperUtils::toStatusCode([&] { assertDataIntegrity(streamRoom); });
}

std::vector<StreamRoom> StreamRoomDataSchemaMapper::validateDecryptAndConvertStreamRooms(
    const std::vector<server::StreamRoomInfo>& streamRooms,
    const std::shared_ptr<core::KeyProvider>& keyProvider
) {
    return core::DataSchemaMapperUtils::batchValidateDecryptVerifyContainers<StreamRoom>(
        streamRooms, keyProvider, _connection,
        [&](const server::StreamRoomInfo& room) { return validateDataIntegrity(room); },
        [](const server::StreamRoomInfo& room) -> core::EncKeyLocation {
            return {.contextId = room.contextId, .resourceId = room.resourceId.value_or("")};
        },
        [&](const server::StreamRoomInfo& room, const core::DecryptedEncKey& key) { return decrypt(room, key); },
        [](const server::StreamRoomInfo& room, uint32_t code) {
            return toLibStreamRoom(room, {}, {}, code, StreamRoomDataSchema::Version::UNKNOWN);
        }
    );
}

StreamRoom StreamRoomDataSchemaMapper::validateDecryptAndConvertStreamRoom(
    const server::StreamRoomInfo& streamRoom,
    const std::shared_ptr<core::KeyProvider>& keyProvider
) {
    return validateDecryptAndConvertStreamRooms({streamRoom}, keyProvider)[0];
}

StreamRoom StreamRoomDataSchemaMapper::toLibStreamRoom(
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