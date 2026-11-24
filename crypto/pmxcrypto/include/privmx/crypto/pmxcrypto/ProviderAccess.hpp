/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTO_PMXCRYPTO_PROVIDERACCESS_HPP_
#define _PRIVMXLIB_CRYPTO_PMXCRYPTO_PROVIDERACCESS_HPP_

#include <privmx/cryptoservice/base/CoreInterfaces.hpp>

namespace privmx {
namespace crypto {
namespace pmximpl {

/**
 * @brief The pmx-crypto provider, registered on first use.
 *
 * **The single registration point in the library**, which is why it lives in this layer rather than
 * in `endpoint/core`: `rpc/` and `privfs/` reach the primitives without going through the endpoint
 * at all, so an accessor that only the endpoint owned would leave them racing to register their
 * own. `endpoint/core/src/crypto/ProviderAccess.cpp` delegates here.
 *
 * Two independent `call_once` guards would not be equivalent to one. Each would check the registry
 * for null and then set it, and that pair is not atomic between them: both could find it empty, both
 * could register, and the second `set` would release the first provider while a reference handed out
 * by `get()` was still on someone's stack.
 */
privmx::cryptoservice::ICryptoProvider& cryptoProvider();

} // namespace pmximpl
} // namespace crypto
} // namespace privmx

#endif // _PRIVMXLIB_CRYPTO_PMXCRYPTO_PROVIDERACCESS_HPP_
