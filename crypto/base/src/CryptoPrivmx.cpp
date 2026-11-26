/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/crypto/CipherType.hpp>
#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/CryptoException.hpp>
#include <privmx/crypto/CryptoPrivmx.hpp>

using namespace privmx;
using namespace privmx::crypto;
using namespace std;

string CryptoPrivmx::privmxDecrypt(bool is_signed, const string& data, const string& key32, const string& iv16, size_t taglen) {
    if (is_signed && data[0] != CipherType::AES_256_CBC_PKCS7_WITH_IV_AND_HMAC_SHA256) {
        throw MissingRequiredSignatureException();
    }
    return Crypto::ctDecrypt(data, key32, iv16, taglen);
}

string CryptoPrivmx::privmxDecrypt(const string& data, const string& key32, const string& iv16, size_t taglen) {
    return privmxDecrypt(false, data, key32, iv16, taglen);
}
