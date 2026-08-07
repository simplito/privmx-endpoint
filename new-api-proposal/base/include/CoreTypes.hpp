/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTOSERVICE_CORETYPES_HPP_
#define _PRIVMXLIB_CRYPTOSERVICE_CORETYPES_HPP_

#include <vector>
#include <string>
#include <memory>
#include <span>

namespace privmx {
namespace cryptoservice {

using Bytes = std::vector<uint8_t>;
using BytesView = std::span<const uint8_t>;

using PrivmxDriverCryptoException = std::runtime_error;

// types of implemented hash functions
enum class Hash  {
    Sha1,      // used directly only in HMAC
    Sha256,
    Sha512     // used directly only in HMAC
//    ,Ripemd160 // probably not used
//    ,Hash160   // probably not used
};

// types of implemented symmetric algorithms
enum class SymAlg {
    Aes256Cbc,      // padding
    Aes256CbcNoPad, // no padding
    Aes256Ecb,      // no padding
    Aes256Gcm       // ACC + tag 
};

// arguments used in symmetric cryptography
struct SymParams {
    SymAlg cipher;
    BytesView key;
    BytesView iv;       // optional for ECB
    BytesView aad = {}; // only for AEAD
    // Bytes tag;       // not used, for AEAD tag is appended to ciphertext
};

// from previous implementation - probably not used
// struct AesOptions {
//     std::string alg;
//     bool padding;
// };


} // cryptoservice
} // privmx

#endif // _PRIVMXLIB_CRYPTOSERVICE_CORETYPES_HPP_