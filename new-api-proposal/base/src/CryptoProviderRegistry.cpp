/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <vector>
#include <string>
#include <memory>
#include <span>

#include "CoreTypes.hpp"
#include "CoreInterfaces.hpp"
#include "CryptoProviderRegistry.hpp"

namespace privmx {
namespace cryptoservice {

std::shared_ptr<ICryptoProvider> CryptoProviderRegistry::_provider(nullptr);

void CryptoProviderRegistry::set(std::shared_ptr<ICryptoProvider> provider)
{
    _provider = provider; // wstrzyknięcie backendu
}

std::shared_ptr<ICryptoProvider> CryptoProviderRegistry::getptr() { // domyślny provider
    return CryptoProviderRegistry::_provider;
    // opcjonalnie: rejestracja wielu po nazwie
}

ICryptoProvider& CryptoProviderRegistry::get() { // domyślny provider
    return *(CryptoProviderRegistry::_provider);
    // opcjonalnie: rejestracja wielu po nazwie
}

} // cryptoservice
} // privmx
