/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_THREAD_THREADDATASCHEMASTRATEGYV4_HPP_
#define _PRIVMXLIB_ENDPOINT_THREAD_THREADDATASCHEMASTRATEGYV4_HPP_

#include <tuple>

#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/encryptors/IDataSchemaStrategy.hpp>
#include <privmx/endpoint/core/encryptors/TypedDataSchemaStrategy.hpp>
#include <privmx/endpoint/core/encryptors/module/ModuleDataEncryptorV4.hpp>
#include <privmx/endpoint/core/encryptors/module/Types.hpp>

#include "privmx/endpoint/thread/ServerTypes.hpp"
#include "privmx/endpoint/thread/Types.hpp"

namespace privmx {
namespace endpoint {
namespace thread {

// clang-format off
class ThreadDataSchemaStrategyV4 : public core::TypedDataSchemaStrategy<
    server::ThreadInfo, 
    core::DecryptedModuleDataV4, 
    std::tuple<Thread, core::DataIntegrityObject>
> {
    // clang-format on
public:
    core::DecryptedModuleDataV4 decrypt(
        const server::ThreadInfo& thread,
        const core::DecryptedEncKey& encKey
    ) const override;
    std::tuple<Thread, core::DataIntegrityObject> convert(
        const server::ThreadInfo& thread,
        const core::DecryptedModuleDataV4& raw
    ) const override;
    std::tuple<Thread, core::DataIntegrityObject> makeErrorResult(
        const server::ThreadInfo& thread,
        int64_t errorCode
    ) const override;

private:
    mutable core::ModuleDataEncryptorV4 _encryptor;
};

} // namespace thread
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_THREAD_THREADDATASCHEMASTRATEGYV4_HPP_
