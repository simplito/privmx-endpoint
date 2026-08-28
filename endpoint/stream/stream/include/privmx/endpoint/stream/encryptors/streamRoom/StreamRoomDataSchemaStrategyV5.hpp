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
#include <privmx/endpoint/core/encryptors/TypedDataSchemaStrategyV5.hpp>
#include <privmx/endpoint/core/encryptors/module/ModuleDataEncryptorV5.hpp>
#include <privmx/endpoint/core/encryptors/module/Types.hpp>

#include "privmx/endpoint/stream/Constants.hpp"
#include "privmx/endpoint/stream/ServerTypes.hpp"
#include "privmx/endpoint/stream/Types.hpp"

namespace privmx {
namespace endpoint {
namespace stream {

// clang-format off
class StreamRoomDataSchemaStrategyV5 : public core::TypedDataSchemaStrategyV5<
    core::ModuleDataEncryptorV5,
    core::dynamic::EncryptedModuleDataV5,
    core::DecryptedModuleDataV5,
    server::StreamRoomInfo,
    StreamRoom
> {
    // clang-format on
public:
    std::tuple<StreamRoom, core::DataIntegrityObject> convert(
        const server::StreamRoomInfo& streamRoom,
        const core::DecryptedModuleDataV5& raw
    ) const override;
    StreamRoom toLibError(const server::StreamRoomInfo& streamRoom, int64_t errorCode) const override;

protected:
    core::dynamic::EncryptedModuleDataV5 getEncryptedData(const server::StreamRoomInfo& model) const override;
};

} // namespace stream
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_STREAMROOMDATASCHEMASTRATEGYV5_HPP_
