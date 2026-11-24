/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/crypto/pmxcrypto/ProviderAccess.hpp>

#include <privmx/endpoint/core/crypto/ProviderAccess.hpp>

namespace cs = privmx::cryptoservice;

// Delegated rather than duplicated. `rpc/` and `privfs/` reach pmx-crypto without passing through
// the endpoint, so the registration has to sit in the layer below this one; two `call_once` guards
// each testing the registry for null and then setting it are not atomic with respect to one another,
// and the loser's `set` would free a provider the winner had already handed out by reference.
cs::ICryptoProvider& privmx::endpoint::core::cryptoProvider() {
    return privmx::crypto::pmximpl::cryptoProvider();
}
