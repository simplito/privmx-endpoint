/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/
#ifndef _PRIVMXLIB_ENDPOINT_CORE_LOCALSEAL_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_LOCALSEAL_HPP_

#include <cstdint>
#include <functional>
#include <optional>
#include <string>

#include <privmx/crypto/ecc/PrivateKey.hpp>

#include "privmx/endpoint/core/PinStoreInterface.hpp"

namespace privmx {
namespace endpoint {
namespace core {

// The slots of the local state (01): `<kind>/<scope>/<identity public key>`, scope = the Bridge
// (`ConnectionImpl::localStateScope`). Labels select the MAC key per kind.
namespace localstate {
constexpr const char* GROUP_PINS = "group-pins";
constexpr const char* GROUP_PINS_LABEL = "privmx/group/pins";
constexpr std::uint8_t GROUP_PINS_VERSION = 1;
constexpr const char* COMMIT_RELEASED = "commit-released";
constexpr const char* COMMIT_RELEASED_LABEL = "privmx/commit/released";
constexpr std::uint8_t COMMIT_RELEASED_VERSION = 1;
} // namespace localstate

// blob = u8 version || body || tag, tag = HMAC-SHA256(K, u8 version || lp(storeKey) || body),
// K = kdf(32, identity private key, label). Binding the slot's key means a blob copied to another slot (another
// identity, Bridge or kind) fails.
std::string sealLocal(
    const ::privmx::crypto::PrivateKey& identity,
    const std::string& label,
    std::uint8_t version,
    const std::string& storeKey,
    const std::string& body
);

// The body, or nullopt when the blob is too short, of another version or its tag does not verify (constant time).
std::optional<std::string> openLocal(
    const ::privmx::crypto::PrivateKey& identity,
    const std::string& label,
    std::uint8_t version,
    const std::string& storeKey,
    const std::string& blob
);

// load -> openLocal -> merge(stored body, or nullopt for nothing stored / unopenable) -> sealLocal ->
// save(expected = loaded). Retries on a compare-and-swap miss; false once the attempts are spent. Throws what the
// store or `merge` throws. `sealed`, when given, receives the blob saved.
bool updateSealed(
    PinStoreInterface& store,
    const ::privmx::crypto::PrivateKey& identity,
    const std::string& storeKey,
    const std::string& label,
    std::uint8_t version,
    const std::function<std::string(const std::optional<std::string>&)>& merge,
    std::string* sealed = nullptr
);

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_LOCALSEAL_HPP_
