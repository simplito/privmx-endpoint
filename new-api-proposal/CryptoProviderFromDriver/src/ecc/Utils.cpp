/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/* Temporary classes to facilitate rewriting 
    from an old implementation to a new one   */


#include <string>

#include "Utils.hpp"

namespace privmx {
namespace cryptoservice {
namespace ecc {

std::string Utils::fillTo32(const std::string& data) {
    if(data.length() >= 32) {
        return data;
    }
    return std::string(32 - data.length(), 0) + data;
}

ICryptoProvider& NewCrypto::get() { 
    return _provider;
}

std::string NewCrypto::randomBytes(size_t len) {
        Bytes r = _provider.randomBytes(len);
    return std::string(r.begin(),r.end());
}

std::string NewCrypto::digest(Hash alg, const std::string data) {
    Bytes hash = _provider.digest(alg, Bytes(data.begin(), data.end()));
    return std::string(hash.begin(),hash.end());
}

std::string NewCrypto::hmac(Hash alg, const std::string key, const std::string data) {
    Bytes hash = _provider.hmac(alg, Bytes(key.begin(), key.end()), Bytes(data.begin(), data.end()));
    return std::string(hash.begin(),hash.end());
}

std::string NewCrypto::encrypt(const SymParamsString& o, std::string plaintext) {
    Bytes ciphertext = _provider.encrypt(
        {o.cipher, Bytes(o.key.begin(), o.key.end()), 
            Bytes(o.iv.begin(), o.iv.end()), o.aad }, 
            Bytes(plaintext.begin(), plaintext.end()));
    return std::string(ciphertext.begin(),ciphertext.end());
}

std::string NewCrypto::decrypt(const SymParamsString& o, std::string ciphertext) {
    Bytes plaintext = _provider.decrypt(
        {o.cipher, Bytes(o.key.begin(), o.key.end()), 
            Bytes(o.iv.begin(), o.iv.end()), o.aad }, 
            Bytes(ciphertext.begin(), ciphertext.end()));
    return std::string(plaintext.begin(),plaintext.end());
}

} // ecc
} // cryptoservice
} // privmx
