/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CRYPTO_TYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_CRYPTO_TYPES_HPP_

#include <string>
#include "privmx/endpoint/crypto/ExtKey.hpp"

namespace privmx {
namespace endpoint {
namespace crypto {

/**
 * Struct containing ECC generated key using BIP-39
 */
struct BIP39_t {

    /**
     * BIP-39 mnemonic.
     */
    std::string mnemonic;
    /**
     * Ecc Key.
     */
    ExtKey ext_key;
    /**
     * BIP-39 entropy.
     */
    std::string entropy;
};

} // crypto
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_CRYPTO_TYPES_HPP_
