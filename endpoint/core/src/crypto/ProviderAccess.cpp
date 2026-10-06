/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <memory>
#include <mutex>

#include <privmx/cryptoservice/base/CryptoProviderRegistry.hpp>
#include <privmx/cryptoservice/provider/CryptoProvider.hpp>

#include <privmx/endpoint/core/crypto/ProviderAccess.hpp>

namespace cs = privmx::cryptoservice;

cs::ICryptoProvider& privmx::endpoint::core::cryptoProvider() {
    static std::once_flag once;
    std::call_once(once, [] {
        if (!cs::CryptoProviderRegistry::getptr()) {
            cs::CryptoProviderRegistry::set(std::make_shared<cs::CryptoProvider>());
        }
    });
    return cs::CryptoProviderRegistry::get();
}
