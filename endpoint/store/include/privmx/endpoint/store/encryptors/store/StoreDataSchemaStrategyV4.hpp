/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_STOREDATASCHEMASTRATEGYV4_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_STOREDATASCHEMASTRATEGYV4_HPP_

#include <tuple>

#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/encryptors/TypedDataSchemaStrategy.hpp>
#include <privmx/endpoint/core/encryptors/module/ModuleDataEncryptorV4.hpp>
#include <privmx/endpoint/core/encryptors/module/Types.hpp>

#include "privmx/endpoint/store/ServerTypes.hpp"
#include "privmx/endpoint/store/Types.hpp"

namespace privmx {
namespace endpoint {
namespace store {

// clang-format off
class StoreDataSchemaStrategyV4 : public core::TypedDataSchemaStrategy<
    server::Store,
    core::DecryptedModuleDataV4,
    std::tuple<Store, core::DataIntegrityObject>
> {
    // clang-format on
public:
    core::DecryptedModuleDataV4 decrypt(const server::Store& store, const core::DecryptedEncKey& encKey) const override;
    std::tuple<Store, core::DataIntegrityObject> convert(
        const server::Store& store,
        const core::DecryptedModuleDataV4& raw
    ) const override;
    std::tuple<Store, core::DataIntegrityObject> makeErrorResult(
        const server::Store& store,
        int64_t errorCode
    ) const override;

private:
    mutable core::ModuleDataEncryptorV4 _encryptor;
};

} // namespace store
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_STOREDATASCHEMASTRATEGYV4_HPP_
