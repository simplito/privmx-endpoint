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
    if (_provider != nullptr)  { 
        _provider -> setSymProvider(nullptr);
    }
    provider -> setSymProvider(provider);
    _provider = provider;          
}

std::shared_ptr<ICryptoProvider> CryptoProviderRegistry::getptr() {  
    return CryptoProviderRegistry::_provider;
}

ICryptoProvider& CryptoProviderRegistry::get() { 
    return *(CryptoProviderRegistry::_provider);
}

} // cryptoservice
} // privmx
