/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_PROVIDERACCESS_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_PROVIDERACCESS_HPP_

#include <privmx/cryptoservice/base/CoreInterfaces.hpp>

namespace privmx {
namespace endpoint {
namespace core {

/**
 * @brief Dostep do providera kryptograficznego pmx-crypto.
 *
 * Rejestruje provider leniwie i jednokrotnie. Jest to konieczne, bo
 * `CryptoProviderRegistry::get()` dereferencuje wskaznik bez sprawdzenia `nullptr`,
 * a sam rejestr nie ma synchronizacji - endpoint zas pracuje na puli watkow.
 */
privmx::cryptoservice::ICryptoProvider& cryptoProvider();

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_PROVIDERACCESS_HPP_
