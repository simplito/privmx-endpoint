/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTOSERVICE_CRYPTOPROVIDERREGISTRY_HPP_
#define _PRIVMXLIB_CRYPTOSERVICE_CRYPTOPROVIDERREGISTRY_HPP_

#include <vector>
#include <string>
#include <memory>
#include <span>

#include "CoreTypes.hpp"
#include "CoreInterfaces.hpp"
// to be replaced with
// #include <privmx/cryptoservice/CoreTypes.hpp>
// #include <privmx/cryptoservice/CoreInterfaces.hpp>

namespace privmx {
namespace cryptoservice {

// --  used to select the backend in RUNTIME (instead of link-time "#ifdef") --
class CryptoProviderRegistry {
public:
    static void set(std::shared_ptr<ICryptoProvider>);     
    static ICryptoProvider& get();                         
    static std::shared_ptr<ICryptoProvider> getptr();      
    ~CryptoProviderRegistry() = default;
private:
    static std::shared_ptr<ICryptoProvider> _provider;
};

} // cryptoservice
} // privmx

#endif // _PRIVMXLIB_CRYPTOSERVICE_CRYPTOPROVIDERREGISTRY_HPP_