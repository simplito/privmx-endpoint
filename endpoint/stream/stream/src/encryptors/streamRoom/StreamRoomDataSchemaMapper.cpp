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
#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/ConvertedExceptions.hpp>
#include <privmx/endpoint/core/CoreConstants.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <set>

#include "privmx/endpoint/stream/StreamException.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::stream;

StreamRoomDataSchemaMapper::StreamRoomDataSchemaMapper(
    const privmx::crypto::PrivateKey& userPrivKey,
    const core::Connection& connection
)
    : _userPrivKey(userPrivKey), _connection(connection) {
    _strategyV5 = std::make_shared<StreamRoomDataSchemaStrategyV5>();
    _strategyMapper.registerStrategy(StreamRoomDataSchema::Version::VERSION_5, _strategyV5);
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
    auto version = getDataStructureVersion(streamRoom.data.back());
    auto strategy = _strategyMapper.getStrategy(static_cast<int64_t>(version));
    if (!strategy) {
        auto e = UnknowStreamRoomFormatException();
        return {
            StreamRoomDataSchemaStrategyV5::toLibStreamRoom(
                streamRoom, {}, {}, e.getCode(), StreamRoomDataSchema::Version::UNKNOWN
            ),
            core::DataIntegrityObject{}
        };
    }
    return strategy->decryptAndConvert(streamRoom, encKey);
}

StreamRoomDataSchema::Version StreamRoomDataSchemaMapper::getDataStructureVersion(
    const server::StreamRoomDataEntry& entry
) {
    if (entry.data.type() == typeid(Poco::JSON::Object::Ptr)) {
        auto versioned = core::dynamic::VersionedData::fromJSON(entry.data);
        switch (versioned.version) {
        case core::ModuleDataSchema::Version::VERSION_5:
            return StreamRoomDataSchema::Version::VERSION_5;
        default:
            return StreamRoomDataSchema::Version::UNKNOWN;
        }
    }
    return StreamRoomDataSchema::Version::UNKNOWN;
}

void StreamRoomDataSchemaMapper::assertDataIntegrity(const server::StreamRoomInfo& streamRoom) {
    const auto& entry = streamRoom.data.back();
    switch (getDataStructureVersion(entry)) {
    case StreamRoomDataSchema::Version::VERSION_5: {
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
    throw UnknowStreamRoomFormatException();
}

uint32_t StreamRoomDataSchemaMapper::validateDataIntegrity(const server::StreamRoomInfo& streamRoom) {
    try {
        assertDataIntegrity(streamRoom);
        return 0;
    } catch (const core::Exception& e) { return e.getCode(); } catch (const privmx::utils::PrivmxException& e) {
        return core::ExceptionConverter::convert(e).getCode();
    } catch (...) { return ENDPOINT_CORE_EXCEPTION_CODE; }
}

std::vector<StreamRoom> StreamRoomDataSchemaMapper::validateDecryptAndConvertStreamRooms(
    const std::vector<server::StreamRoomInfo>& streamRooms,
    const std::shared_ptr<core::KeyProvider>& keyProvider
) {
    if (streamRooms.empty()) {
        return {};
    }

    std::vector<StreamRoom> result(streamRooms.size());
    std::vector<core::DataIntegrityObject> result_dio(streamRooms.size());
    std::set<std::string> seenRandomIds;

    for (size_t i = 0; i < streamRooms.size(); i++) {
        auto code = validateDataIntegrity(streamRooms[i]);
        if (code != 0) {
            result[i] = StreamRoomDataSchemaStrategyV5::toLibStreamRoom(
                streamRooms[i], {}, {}, code, StreamRoomDataSchema::Version::UNKNOWN
            );
        }
    }

    core::KeyDecryptionAndVerificationRequest keyRequest;
    for (size_t i = 0; i < streamRooms.size(); i++) {
        if (result[i].statusCode != 0) {
            continue;
        }
        const auto& room = streamRooms[i];
        core::EncKeyLocation loc{.contextId = room.contextId, .resourceId = room.resourceId.value_or("")};
        keyRequest.addOne(room.keys, room.data.back().keyId, loc);
    }
    auto roomKeys = keyProvider->getKeysAndVerify(keyRequest);

    for (size_t i = 0; i < streamRooms.size(); i++) {
        if (result[i].statusCode != 0) {
            continue;
        }
        const auto& room = streamRooms[i];
        core::EncKeyLocation loc{.contextId = room.contextId, .resourceId = room.resourceId.value_or("")};
        try {
            auto it = roomKeys.find(loc);
            if (it == roomKeys.end()) {
                throw UnknowStreamRoomFormatException();
            }
            auto [decryptedRoom, dio] = decrypt(room, it->second.at(room.data.back().keyId));
            result[i] = decryptedRoom;
            result_dio[i] = dio;
            if (!seenRandomIds.insert(dio.randomId + "-" + std::to_string(dio.timestamp)).second) {
                result[i].statusCode = core::DataIntegrityObjectDuplicatedException().getCode();
            }
        } catch (const core::Exception& e) {
            result[i] = StreamRoomDataSchemaStrategyV5::toLibStreamRoom(
                room, {}, {}, e.getCode(), StreamRoomDataSchema::Version::UNKNOWN
            );
        }
    }

    std::vector<core::VerificationRequest> verifyRequests;
    std::vector<size_t> verifyIndices;
    for (size_t i = 0; i < result.size(); i++) {
        if (result[i].statusCode != 0) {
            continue;
        }
        verifyRequests.push_back(
            {.contextId = result[i].contextId,
             .senderId = result[i].lastModifier,
             .senderPubKey = result_dio[i].creatorPubKey,
             .date = result[i].lastModificationDate,
             .bridgeIdentity = result_dio[i].bridgeIdentity}
        );
        verifyIndices.push_back(i);
    }
    auto verified = _connection.getImpl()->getUserVerifier()->verify(verifyRequests);
    for (size_t j = 0; j < verifyIndices.size(); j++) {
        result[verifyIndices[j]].statusCode = verified[j] ?
            0 :
            core::ExceptionConverter::getCodeOfUserVerificationFailureException();
    }
    return result;
}

StreamRoom StreamRoomDataSchemaMapper::validateDecryptAndConvertStreamRoom(
    const server::StreamRoomInfo& streamRoom,
    const std::shared_ptr<core::KeyProvider>& keyProvider
) {
    return validateDecryptAndConvertStreamRooms({streamRoom}, keyProvider)[0];
}
