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

int CryptoPrivmx::privmxGetBlockSize(const PrivmxEncryptOptions& options, int block_size) {
    int size = block_size - 1;
    if (options.attachIv) {
        size -= 16;
    }
    if (options.hmac != PrivmxEncryptOptions::NO_HMAC) {
        size -= options.taglen;
    }
    return size - (size % 16) - 1;
}

string CryptoPrivmx::privmxEncrypt(const PrivmxEncryptOptions& options, const string& data, const string& key, string iv) {
    if (key.length() != 32) {
        throw EncryptInvalidKeyLengthException("required: 32, received: " + to_string(key.length()));
    }
    if (options.algorithm == PrivmxEncryptOptions::AES_256_CBC) {
        if (options.hmac != PrivmxEncryptOptions::NO_HMAC) {
            if (options.hmac != PrivmxEncryptOptions::SHA_256 || !options.attachIv) {
                throw OnlyHmacSHA256WithIvIsSupportedForAES256CBCException();
            }
            if (options.deterministic) {
                if (options.attachIv) {
                    throw CannotPassIvToDeterministicAES256CBCHmacSHA256Exception();
                }
            } else {
                if (iv.empty()) {
                    iv = Crypto::randomBytes(16);
                }
                return Crypto::ctAes256CbcPkcs7WithIvAndHmacSha256(data, key, iv, options.taglen);
            }
        }
        if (iv.empty()) {
            iv = Crypto::randomBytes(16);
        }
        if (options.attachIv) {
            return Crypto::ctAes256CbcPkcs7WithIv(data, key, iv);
        }
        return Crypto::ctAes256CbcPkcs7NoIv(data, key, iv);
    } else if (options.algorithm == PrivmxEncryptOptions::XTEA_ECB) {
        if (options.hmac != PrivmxEncryptOptions::NO_HMAC || !iv.empty() || options.attachIv) {
            throw XTEAECBEncryptionDoesntSupportHmacAndIvException();
        }
        throw NotImplementedException();
    }
    throw UnsupportedEncryptionAlgorithmException();
}

string CryptoPrivmx::privmxDecrypt(bool is_signed, const string& data, const string& key32, const string& iv16, size_t taglen) {
    if (is_signed && data[0] != CipherType::AES_256_CBC_PKCS7_WITH_IV_AND_HMAC_SHA256) {
        throw MissingRequiredSignatureException();
    }
    return Crypto::ctDecrypt(data, key32, iv16, taglen);
}

string CryptoPrivmx::privmxDecrypt(const string& data, const string& key32, const string& iv16, size_t taglen) {
    return privmxDecrypt(false, data, key32, iv16, taglen);
}
