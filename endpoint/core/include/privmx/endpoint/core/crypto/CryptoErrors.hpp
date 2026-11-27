/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_CRYPTOERRORS_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_CRYPTOERRORS_HPP_

#include <exception>
#include <string>

#include <privmx/utils/PrivmxException.hpp>

#include "privmx/endpoint/core/Exception.hpp"

namespace privmx {
namespace endpoint {
namespace core {

/**
 * @brief Translates pmx-crypto exceptions into the endpoint's exception hierarchy.
 *
 * Why this has to exist at all: `cryptoservice::Exception` derives from `std::exception`, not from
 * `privmx::utils::PrivmxException`. The whole public API boundary of the endpoint catches
 * `PrivmxException` only and passes it through `ExceptionConverter`, so an exception from
 * pmx-crypto would cross that boundary untouched — as a type no wrapper (Java, Swift, JS)
 * recognises.
 *
 * The translation happens at the source rather than at the API boundary, for two reasons:
 *  - that boundary is some 250 `catch` blocks across a dozen or so `*Api.cpp` files,
 *  - only here is the calling context known (key import, verification, decryption), and the
 *    pmx-crypto exceptions carry no code of their own (every one has `code == 0`).
 *
 * The endpoint's entire contact surface with pmx-crypto is the files in `core/src/crypto/`, so
 * wrapping their calls closes that scope tightly.
 */
class CryptoErrors {
public:
    /**
     * Throws the `endpoint::crypto::*` counterpart of a pmx-crypto exception.
     *
     * @param e the exception caught at the pmx-crypto boundary
     * @param context name of the endpoint operation, appended to the description
     */
    [[noreturn]] static void rethrow(const std::exception& e, const std::string& context);
};

/**
 * Runs `fn`, translating pmx-crypto exceptions. Returns whatever `fn` returns.
 *
 * It catches `std::exception` rather than `cryptoservice::Exception`, because pmx-crypto also
 * throws a bare `std::runtime_error` (`PrivmxDriverCryptoException` is an alias for it). Exceptions
 * that already belong to the endpoint's hierarchy pass through unchanged — otherwise the wrappers'
 * own validation (say `MalformedEncryptionKeyException` from an empty key) would lose its code.
 */
template<typename F>
decltype(auto) mapCryptoErrors(const char* context, F&& fn) {
    try {
        return fn();
    } catch (const Exception&) { throw; } catch (const privmx::utils::PrivmxException&) {
        throw;
    } catch (const std::exception& e) {
        CryptoErrors::rethrow(e, context);
        throw; // unreachable — `rethrow` is [[noreturn]]; this quiets flow analysis
    }
}

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_CRYPTOERRORS_HPP_
