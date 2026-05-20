/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STREAM_STREAMROOMDATASCHEMASTRATEGYV5_HPP_
#define _PRIVMXLIB_ENDPOINT_STREAM_STREAMROOMDATASCHEMASTRATEGYV5_HPP_

#include <tuple>

#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/DynamicTypes.hpp>
#include <privmx/endpoint/core/encryptors/TypedDataSchemaStrategy.hpp>
#include <privmx/endpoint/core/encryptors/module/ModuleDataEncryptorV5.hpp>
#include <privmx/endpoint/core/encryptors/module/Types.hpp>

#include "privmx/endpoint/stream/Constants.hpp"
#include "privmx/endpoint/stream/ServerTypes.hpp"
#include "privmx/endpoint/stream/Types.hpp"

namespace privmx {
namespace endpoint {
namespace stream {

// clang-format off
class StreamRoomDataSchemaStrategyV5 : public core::TypedDataSchemaStrategy<
    server::StreamRoomInfo,
    core::DecryptedModuleDataV5,
    std::tuple<StreamRoom, core::DataIntegrityObject>
> {
    // clang-format on
public:
    core::DecryptedModuleDataV5 decrypt(
        const server::StreamRoomInfo& streamRoom,
        const core::DecryptedEncKey& encKey
    ) const override;
    std::tuple<StreamRoom, core::DataIntegrityObject> convert(
        const server::StreamRoomInfo& streamRoom,
        const core::DecryptedModuleDataV5& raw
    ) const override;
    std::tuple<StreamRoom, core::DataIntegrityObject> makeErrorResult(
        const server::StreamRoomInfo& streamRoom,
        int64_t errorCode
    ) const override;
    core::DataIntegrityObject getDIOAndAssertIntegrity(const core::dynamic::EncryptedModuleDataV5& encData) const;

    static StreamRoom toLibStreamRoom(
        const server::StreamRoomInfo& info,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        int64_t statusCode,
        int64_t schemaVersion
    );

private:
    mutable core::ModuleDataEncryptorV5 _encryptor;
};

} // namespace stream
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_STREAMROOMDATASCHEMASTRATEGYV5_HPP_
