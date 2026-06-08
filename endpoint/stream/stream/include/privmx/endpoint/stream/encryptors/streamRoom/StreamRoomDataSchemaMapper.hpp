/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STREAM_STREAMROOMDATASCHEMAMAPPER_HPP_
#define _PRIVMXLIB_ENDPOINT_STREAM_STREAMROOMDATASCHEMAMAPPER_HPP_

#include <cstdint>
#include <memory>
#include <string>
#include <tuple>
#include <vector>

#include <Poco/Dynamic/Var.h>
#include <privmx/endpoint/core/BaseModuleDataSchemaMapper.hpp>
#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/DynamicTypes.hpp>
#include <privmx/endpoint/core/KeyProvider.hpp>
#include <privmx/endpoint/core/TimestampValidator.hpp>
#include <privmx/endpoint/core/encryptors/VersionStrategyMapper.hpp>
#include <privmx/endpoint/core/encryptors/module/Types.hpp>

#include "privmx/endpoint/stream/Constants.hpp"
#include "privmx/endpoint/stream/ServerTypes.hpp"
#include "privmx/endpoint/stream/Types.hpp"
#include "privmx/endpoint/stream/encryptors/streamRoom/StreamRoomDataSchemaStrategyV5.hpp"

namespace privmx {
namespace endpoint {
namespace stream {

class StreamRoomDataSchemaMapper : public core::BaseModuleDataSchemaMapper {
public:
    StreamRoomDataSchemaMapper(const privmx::crypto::PrivateKey& userPrivKey, const core::Connection& connection);

    Poco::Dynamic::Var encrypt(const core::ModuleDataToEncryptV5& data, const std::string& key);

    std::tuple<StreamRoom, core::DataIntegrityObject> decrypt(
        const server::StreamRoomInfo& streamRoom,
        const core::DecryptedEncKey& encKey
    );

    void assertDataIntegrity(const server::StreamRoomInfo& streamRoom);

    uint32_t validateDataIntegrity(const server::StreamRoomInfo& streamRoom);

    std::vector<StreamRoom> validateDecryptAndConvertStreamRooms(
        const std::vector<server::StreamRoomInfo>& streamRooms,
        const std::shared_ptr<core::KeyProvider>& keyProvider
    );

    StreamRoom validateDecryptAndConvertStreamRoom(
        const server::StreamRoomInfo& streamRoom,
        const std::shared_ptr<core::KeyProvider>& keyProvider
    );
    static StreamRoom toLibStreamRoom(
        const server::StreamRoomInfo& info,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        int64_t statusCode,
        int64_t schemaVersion
    );

private:
    core::VersionStrategyMapper<server::StreamRoomInfo, std::tuple<StreamRoom, core::DataIntegrityObject>>
        _strategyMapper;
    std::shared_ptr<StreamRoomDataSchemaStrategyV5> _strategyV5;
};

} // namespace stream
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_STREAMROOMDATASCHEMAMAPPER_HPP_
