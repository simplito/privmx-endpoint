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
    Sha1,      // probably used directly only in HMAC
    Sha256,
    Sha512     // probably used directly only in HMAC
//    ,Ripemd160 // probably not used
//    ,Hash160   // probably not used
};

// types of implemented symmetric algorithms
enum class SymAlg {
    Aes256Cbc,      // AES 256 CBC, padding
    Aes256CbcNoPad, // AES 256 CBC, no padding
    Aes256Ecb,      // AES 256 ECB, no padding
    Aes256Gcm       // AES 256 GCM, ACC + tag 
};

// types of implemented key derivation functions
enum class Kdf {
    Kdf,        // HMAC-based Key Derivation Function
    Pbkdf2,     // Password-Based Key Derivation Function 2
    Prf12       // TLS 1.2 Pseudo-Random Function 
};

// arguments used in symmetric cryptography
struct SymParams {
    SymAlg cipher;
    BytesView key;
    BytesView iv;       // optional for ECB
    BytesView aad = {}; // only for AEAD
    // Bytes tag;       // not used, for AEAD tag is appended to ciphertext
};

// arguments used in key derivation functions 
struct KdfParams {
    Kdf kdf;             // algorithm
    size_t length;       // length of resulting key
//  Hash prf;            // Hash function - SHA512 for PBKDF2, SHA256 for Prf12 and Kdf
    int rounds;          // only for Pbkdf2
    BytesView salt = {}; // salt Pbkdf2, seed for Prf12 
    std::string label = {}; // only for Kdf (maybe it should be replaced by "salt"?)
};

// from previous implementation - probably not used
// struct AesOptions {
//     std::string alg;
//     bool padding;
// };

} // cryptoservice
} // privmx

#endif // _PRIVMXLIB_CRYPTOSERVICE_CORETYPES_HPP_