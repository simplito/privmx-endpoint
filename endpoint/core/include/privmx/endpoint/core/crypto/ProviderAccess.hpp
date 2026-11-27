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
 * @brief Access to the pmx-crypto cryptographic provider.
 *
 * Registers the provider lazily and exactly once. That is necessary because
 * `CryptoProviderRegistry::get()` dereferences a pointer without a `nullptr` check, and the
 * registry itself has no synchronisation — while the endpoint works on a thread pool.
 */
privmx::cryptoservice::ICryptoProvider& cryptoProvider();

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_PROVIDERACCESS_HPP_
