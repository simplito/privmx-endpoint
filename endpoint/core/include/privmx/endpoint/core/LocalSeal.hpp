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

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>

#include <privmx/endpoint/core/crypto/PrivateKey.hpp>

#include "privmx/endpoint/core/PinStoreInterface.hpp"

namespace privmx {
namespace endpoint {
namespace core {

// blob = u8 version || body || tag, tag = HMAC-SHA256(K, u8 version || lp(storeKey) || body),
// K = kdf(32, identity private key, label). Binding the slot's key means a blob copied to another slot (another
// identity, Bridge or kind) fails. (`seal`, `open`)
class LocalSeal {
public:
    // The slots of the local state: `<kind>/<scope>/<identity public key>`, scope = the Bridge
    // (`ConnectionImpl::localStateScope`). Labels select the MAC key per kind.
    static constexpr const char* GROUP_PINS = "group-pins";
    static constexpr const char* GROUP_PINS_LABEL = "privmx/group/pins";
    static constexpr std::uint8_t GROUP_PINS_VERSION = 1;

    // The four values a blob is bound to. They are taken once, together, because sealing and opening under
    // anything but the same four is not an error anywhere — the blob simply opens as nothing.
    LocalSeal(
        const PrivateKey& identity,
        const std::string& label,
        std::uint8_t version,
        const std::string& storeKey
    );

    std::string seal(const std::string& body) const;

    // The body, or nullopt when the blob is too short, of another version or its tag does not verify (constant time).
    std::optional<std::string> open(const std::string& blob) const;

    // load -> open -> merge(stored body, or nullopt for nothing stored / unopenable) -> seal -> save(expected =
    // loaded). Retries on a compare-and-swap miss; false once the attempts are spent. Throws what the store or
    // `merge` throws.
    bool update(
        PinStoreInterface& store,
        const std::function<std::string(const std::optional<std::string>&)>& merge
    ) const;

private:
    static constexpr std::size_t TAG_SIZE = 32;
    // Limit: 8 compare-and-swap attempts; a store contended harder than that fails the save (logged, retried later).
    static constexpr int CAS_ATTEMPTS = 8;

    std::string tagOf(const std::string& body) const;
    static bool equalInConstantTime(const std::string& a, const std::string& b);

    PrivateKey _identity;
    std::string _label;
    std::uint8_t _version;
    std::string _storeKey;
};

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_LOCALSEAL_HPP_
