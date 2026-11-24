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

#include <privmx/crypto/pmxcrypto/ProviderAccess.hpp>

namespace cs = privmx::cryptoservice;

cs::ICryptoProvider& privmx::crypto::pmximpl::cryptoProvider() {
    static std::once_flag once;
    std::call_once(once, [] {
        // Still conditional: an embedder may have registered its own provider before any PrivMX code
        // ran, and that choice is the point of the registry being settable at all.
        if (!cs::CryptoProviderRegistry::getptr()) {
            cs::CryptoProviderRegistry::set(std::make_shared<cs::CryptoProvider>());
        }
    });
    return cs::CryptoProviderRegistry::get();
}
