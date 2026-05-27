/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/stream/encryptors/streamRoom/StreamRoomDataSchemaStrategyV5.hpp"
#include "privmx/endpoint/stream/encryptors/streamRoom/StreamRoomDataSchemaMapper.hpp"

#include <privmx/endpoint/core/Factory.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::stream;

core::dynamic::EncryptedModuleDataV5 StreamRoomDataSchemaStrategyV5::getEncryptedData(
    const server::StreamRoomInfo& model
) const {
    return core::dynamic::EncryptedModuleDataV5::fromJSON(model.data.back().data);
}

std::tuple<StreamRoom, core::DataIntegrityObject> StreamRoomDataSchemaStrategyV5::convert(
    const server::StreamRoomInfo& streamRoom,
    const core::DecryptedModuleDataV5& raw
) const {
    return {
        StreamRoomDataSchemaMapper::toLibStreamRoom(
            streamRoom, raw.publicMeta, raw.privateMeta, raw.statusCode, StreamRoomDataSchema::Version::VERSION_5
        ),
        raw.dio
    };
}

StreamRoom StreamRoomDataSchemaStrategyV5::toLibError(const server::StreamRoomInfo& streamRoom, int64_t errorCode) const {
    return StreamRoomDataSchemaMapper::toLibStreamRoom(streamRoom, {}, {}, errorCode, StreamRoomDataSchema::Version::VERSION_5);
}
