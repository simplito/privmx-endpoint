/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTOSERVICE_ECCIMPL_UTILS_HPP_
#define _PRIVMXLIB_CRYPTOSERVICE_ECCIMPL_UTILS_HPP_

/* Temporary classes to facilitate rewriting 
    from an old implementation to a new one   */

#include <memory>
#include <string>

#include "CoreTypes.hpp"

#include "CryptoProviderFromDriver.hpp"

namespace privmx {
namespace cryptoservice {
namespace ecc {

struct SymParamsString {
    SymAlg cipher;
    std::string key;
    std::string iv;       // optional for ECB
    BytesView aad = {}; // only for AEAD
    // Bytes tag;       // not used, for AEAD tag is appended to ciphertext
};

class NewCrypto
{
public:
    static ICryptoProvider& get();
    static std::string randomBytes(size_t len);
    static std::string digest(Hash alg, const std::string data);
    static std::string hmac(Hash alg, const std::string key, const std::string data);
    static std::string encrypt(const SymParamsString&, std::string plaintext);  
    static std::string decrypt(const SymParamsString&, std::string ciphertext);

private:
    // static std::shared_ptr<ICryptoProvider> _provider = std::make_shared<CryptoProviderFromDriver>();
    static CryptoProviderFromDriver _provider;
};

class Utils
{
public:
    static std::string fillTo32(const std::string& data);
};





} // ecc
} // cryptoservice
// } // crypto
} // privmx

#endif // _PRIVMXLIB_CRYPTOSERVICE_ECCIMPL_UTILS_HPP_