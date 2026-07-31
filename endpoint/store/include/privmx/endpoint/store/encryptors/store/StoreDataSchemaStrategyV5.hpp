/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_STOREDATASCHEMASTRATEGYV5_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_STOREDATASCHEMASTRATEGYV5_HPP_

#include <tuple>

#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/DynamicTypes.hpp>
#include <privmx/endpoint/core/encryptors/TypedDataSchemaStrategyV5.hpp>
#include <privmx/endpoint/core/encryptors/module/ModuleDataEncryptorV5.hpp>
#include <privmx/endpoint/core/encryptors/module/Types.hpp>

#include "privmx/endpoint/store/ServerTypes.hpp"
#include "privmx/endpoint/store/Types.hpp"

namespace privmx {
namespace endpoint {
namespace store {

// clang-format off
class StoreDataSchemaStrategyV5 : public core::TypedDataSchemaStrategyV5<
    core::ModuleDataEncryptorV5,
    core::dynamic::EncryptedModuleDataV5,
    core::DecryptedModuleDataV5,
    server::Store,
    Store
> {
    // clang-format on
public:
    std::tuple<Store, core::DataIntegrityObject> convert(
        const server::Store& store,
        const core::DecryptedModuleDataV5& raw
    ) const override;
    Store toLibError(const server::Store& store, int64_t errorCode) const override;
    core::dynamic::EncryptedModuleDataV5 encrypt(
        const core::ModuleDataToEncryptV5& data,
        const privmx::crypto::PrivateKey& userPrivKey,
        const std::string& key
    ) const;

protected:
    core::dynamic::EncryptedModuleDataV5 getEncryptedData(const server::Store& model) const override;
};

} // namespace store
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_STOREDATASCHEMASTRATEGYV5_HPP_
