/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/*****    "reimplements" privmx-endpoint/crypto/openssl   *****/

#include <string.h>
#include <stdlib.h>

#include <memory>
#include <string>
#include <vector>
#include <functional>

#include <fstream>

#include "CoreTypes.hpp"
#include "CoreInterfaces.hpp"
#include "CryptoProviderFromOpenssl.hpp"

#include <Poco/Random.h>

#include <Poco/RandomStream.h>

#include <Poco/SHA1Engine.h>
#include <Poco/SHA2Engine.h>

#include <Poco/HMACEngine.h>

#include <Poco/Crypto/CipherFactory.h>
#include <Poco/Crypto/CipherKey.h>
#include <Poco/ByteOrder.h>
#include <Poco/Crypto/Cipher.h>
// #include <Poco/Crypto/Crypto.h>

#include <openssl/evp.h>
#include <openssl/aes.h>

using Poco::ByteOrder;

using namespace Poco::Crypto;


namespace privmx {
namespace cryptoservice {

// #include <openssl/rand.h>

// #include <Poco/ByteOrder.h>
// #include <Poco/Crypto/Crypto.h>
// #include <Poco/Crypto/Cipher.h>
// #include <Poco/Crypto/CipherFactory.h>
// #include <Poco/Crypto/CipherKey.h>
// #include <Poco/Crypto/DigestEngine.h>
// #include <Poco/Crypto/OpenSSLInitializer.h>
// #include <Poco/HMACEngine.h>
// #include <Poco/RandomStream.h>

// using Poco::RandomBuf;

uint32_t CryptoProviderFromOpenssl::version() const { return 0; }

std::string CryptoProviderFromOpenssl::name() const { 
    return std::string("reimplementation of privmx-endpoint/crypto/openssl"); 
}

Bytes CryptoProviderFromOpenssl::randomBytes(size_t length)
{
    Poco::RandomBuf random_buf;
    char buffer[length];
    random_buf.readFromDevice(buffer, length);
    return Bytes(buffer, buffer+length);
}

Bytes CryptoProviderFromOpenssl::digest(Hash alg, BytesView data)
{
    std::string message(data.begin(), data.end());
    if (alg == Hash::Sha1) {
        Poco::SHA1Engine sha1;
        sha1.update(message);
        Poco::DigestEngine::Digest digest = sha1.digest();
        return Bytes(digest.begin(), digest.end());
    } else if (alg == Hash::Sha256) {
        Poco::SHA2Engine256 sha256;
        sha256.update(message);
        Poco::DigestEngine::Digest digest = sha256.digest();
        return Bytes(digest.begin(), digest.end());
    } else if (alg == Hash::Sha512) {
        Poco::SHA2Engine512 sha512;
        sha512.update(message);
        Poco::DigestEngine::Digest digest = sha512.digest();
        return Bytes(digest.begin(), digest.end());
    // } else if (alg == Hash::Ripemd160) {
    //     unsigned char* md[20];
    //     if(RIPEMD160(data.data(), data.size(), md) == NULL) {
    //         throw PrivmxDriverCryptoException("Digest: RIPEMD160 fail");
    //     }
    //     return Bytes(buffer, buffer+length);
    // } else if (alg == Hash::Hash160) {
    //     return digest(Hash::Ripemd160, digest(Hash::Sha256, data));
    } else {
        throw PrivmxDriverCryptoException("Digest: Unknown protocol");
    }
}

Bytes CryptoProviderFromOpenssl::hmac(Hash alg, BytesView key, BytesView data) 
{
    std::string keyStr(key.begin(), key.end());
    std::string dataStr(data.begin(), data.end());
    if (alg == Hash::Sha1) {
        Poco::HMACEngine<Poco::SHA1Engine> hmac(keyStr);
        hmac.update(dataStr);
        Poco::DigestEngine::Digest digest = hmac.digest();
        return Bytes(digest.begin(), digest.end());
    } else if (alg == Hash::Sha256) {
        Poco::HMACEngine<Poco::SHA2Engine256> hmac(keyStr);
        hmac.update(dataStr);
        Poco::DigestEngine::Digest digest = hmac.digest();
        return Bytes(digest.begin(), digest.end());
    } else if (alg == Hash::Sha512) {
        Poco::HMACEngine<Poco::SHA2Engine512> hmac(keyStr);
        hmac.update(dataStr);
        Poco::DigestEngine::Digest digest = hmac.digest();
        return Bytes(digest.begin(), digest.end());
    } else {
        throw PrivmxDriverCryptoException("Digest: Unknown protocol");
    }
}

Bytes CryptoProviderFromOpenssl::encrypt(const SymParams& opt, BytesView plaintext) 
{
    std::string message(plaintext.begin(), plaintext.end());
    if (opt.cipher == SymAlg::Aes256Cbc) {
        CipherFactory& factory = CipherFactory::defaultFactory();
        Cipher::ByteVec vkey(opt.key.begin(), opt.key.end());
        Cipher::ByteVec viv(opt.iv.begin(), opt.iv.end());
        CipherKey cipher_key("AES-256-CBC", vkey, viv);
        Cipher::Ptr cipher = factory.createCipher(cipher_key);
        std::string result = cipher->encryptString(message);
        return Bytes(result.begin(), result.end());
    } else if (opt.cipher == SymAlg::Aes256CbcNoPad) {
        std::unique_ptr<EVP_CIPHER_CTX, std::function<decltype(EVP_CIPHER_CTX_free)>> 
                ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
        EVP_CIPHER_CTX* raw_ctx = ctx.get();
        if (raw_ctx == NULL) {
            throw PrivmxDriverCryptoException("Encrypt AES-256-CBC: Unable to set encryption context");
        }
        EVP_CIPHER_CTX_init(raw_ctx);
        if (EVP_EncryptInit_ex(raw_ctx, EVP_aes_256_cbc(), NULL, 
                opt.key.data(), opt.iv.data()) != 1) {
            throw PrivmxDriverCryptoException("Encrypt AES-256-CBC: Encryption initialization failed");
        }
        if (EVP_CIPHER_CTX_set_padding(raw_ctx, 0) != 1) {
            throw PrivmxDriverCryptoException("Encrypt AES-256-CBC: Encryption padding failed");
        }
        int data_len = plaintext.size();
        unsigned char buf[data_len];
        int buf_len = 0;
        if (EVP_EncryptUpdate(raw_ctx, buf, &buf_len, plaintext.data(), plaintext.size()) != 1) {
            throw PrivmxDriverCryptoException("Encrypt AES-256-CBC: Encryption update failed");
        }
        int final_len = 0;
        if (EVP_EncryptFinal_ex(raw_ctx, buf + buf_len, &final_len) != 1) {
            throw PrivmxDriverCryptoException("Encrypt AES-256-CBC: Encryption finalization failed");
        }
        buf_len += final_len;
        EVP_CIPHER_CTX_cleanup(raw_ctx);
        return Bytes(buf, buf+buf_len);
    } else if (opt.cipher == SymAlg::Aes256Ecb) {
        std::unique_ptr<EVP_CIPHER_CTX, std::function<decltype(EVP_CIPHER_CTX_free)>> 
                ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
        EVP_CIPHER_CTX* raw_ctx = ctx.get();
        if (raw_ctx == NULL) {
            throw PrivmxDriverCryptoException("Encrypt AES-256-ECB: Unable to set encryption context");
        }
        EVP_CIPHER_CTX_init(raw_ctx);
        if (EVP_EncryptInit_ex(raw_ctx, EVP_aes_256_ecb(), NULL, opt.key.data(), NULL) != 1) {
            throw PrivmxDriverCryptoException("Encrypt AES-256-ECB: Encryption initialization failed");
        }
        if (EVP_CIPHER_CTX_set_padding(raw_ctx, 0) != 1) {
            throw PrivmxDriverCryptoException("Encrypt AES-256-ECB: Encryption padding failed");
        }
        int data_len = plaintext.size();
        unsigned char buf[data_len];
        int buf_len = 0;
        if (EVP_EncryptUpdate(raw_ctx, buf, &buf_len, plaintext.data(), plaintext.size()) != 1) {
            throw PrivmxDriverCryptoException("Encrypt AES-256-CBC: Encryption update failed");
        }
        int final_len = 0;
        if (EVP_EncryptFinal_ex(raw_ctx, buf + buf_len, &final_len) != 1) {
            throw PrivmxDriverCryptoException("Encrypt AES-256-CBC: Encryption finalization failed");
        }
        buf_len += final_len;
        EVP_CIPHER_CTX_cleanup(raw_ctx);
        // const char* buf_as_char = reinterpret_cast<char*>(buf);
        // return string(buf_as_char, buf_len);
        return Bytes(buf, buf+buf_len);
    } else if (opt.cipher == SymAlg::Aes256Gcm) {
        throw PrivmxDriverCryptoException("Symmetric Decryption: AES-256-GCM not implemented");
    // } else if (opt.cipher == SymAlg::Aes256GcmAead) {
    } else {
        throw PrivmxDriverCryptoException("Symmetric Ecryption: Unknown protocol");
    }
}

Bytes CryptoProviderFromOpenssl::decrypt(const SymParams& opt, BytesView ciphertext) 
{
    std::string message(ciphertext.begin(), ciphertext.end());
    if (opt.cipher == SymAlg::Aes256Cbc) {
        CipherFactory& factory = CipherFactory::defaultFactory();
        Cipher::ByteVec vkey(opt.key.begin(), opt.key.end());
        Cipher::ByteVec viv(opt.iv.begin(), opt.iv.end());
        CipherKey cipher_key("AES-256-CBC", vkey, viv);
        Cipher::Ptr cipher = factory.createCipher(cipher_key);
        std::string result = cipher->decryptString(message);
        return Bytes(result.begin(), result.end());
    } else if (opt.cipher == SymAlg::Aes256CbcNoPad) {
        std::unique_ptr<EVP_CIPHER_CTX, std::function<decltype(EVP_CIPHER_CTX_free)>> 
                ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
        EVP_CIPHER_CTX* raw_ctx = ctx.get();
        if (raw_ctx == NULL) {
            throw PrivmxDriverCryptoException("Decrypt AES-256-CBC: Unable to set decryption context");
        }
        EVP_CIPHER_CTX_init(raw_ctx);
        if (EVP_DecryptInit_ex(raw_ctx, EVP_aes_256_cbc(), NULL, opt.key.data(), opt.iv.data()) != 1) {
            throw PrivmxDriverCryptoException("Decrypt AES-256-CBC: Decryption initialization failed");
        }
        if (EVP_CIPHER_CTX_set_padding(raw_ctx, 0) != 1) {
            throw PrivmxDriverCryptoException("Decrypt AES-256-CBC: Decryption padding failed");
        }
        int data_len = ciphertext.size();
        unsigned char buf[data_len];
        int buf_len = 0;
        if (EVP_DecryptUpdate(raw_ctx, buf, &buf_len, ciphertext.data(), ciphertext.size()) != 1) {
            throw PrivmxDriverCryptoException("Decrypt AES-256-CBC: Decryption update failed");
        }
        int final_len = 0;
        if (EVP_DecryptFinal_ex(raw_ctx, buf + buf_len, &final_len) != 1) {
            throw PrivmxDriverCryptoException("Decrypt AES-256-CBC: Decryption finalization failed");
        }
        buf_len += final_len;
        EVP_CIPHER_CTX_cleanup(raw_ctx);
        return Bytes(buf, buf+buf_len);
    } else if (opt.cipher == SymAlg::Aes256Ecb) {
        std::unique_ptr<EVP_CIPHER_CTX, std::function<decltype(EVP_CIPHER_CTX_free)>> 
                ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
        EVP_CIPHER_CTX* raw_ctx = ctx.get();
        if (raw_ctx == NULL) {
            throw PrivmxDriverCryptoException("Decrypt AES-256-ECB: Decryption initialization failed");
        }
        EVP_CIPHER_CTX_init(raw_ctx);
        if (EVP_DecryptInit_ex(raw_ctx, EVP_aes_256_ecb(), NULL, opt.key.data(), NULL) != 1) {
            throw PrivmxDriverCryptoException("Decrypt AES-256-ECB: Decryption initialization failed");
        }
        if (EVP_CIPHER_CTX_set_padding(raw_ctx, 0) != 1) {
            throw PrivmxDriverCryptoException("Decrypt AES-256-ECB: Decryption padding failed");
        }
        int data_len = ciphertext.size();
        unsigned char buf[data_len];
        int buf_len = 0;
        if (EVP_DecryptUpdate(raw_ctx, buf, &buf_len, ciphertext.data(), ciphertext.size()) != 1) {
            throw PrivmxDriverCryptoException("Decrypt AES-256-ECB: Decryption update failed");
        }
        int final_len = 0;
        if (EVP_DecryptFinal_ex(raw_ctx, buf + buf_len, &final_len) != 1) {
            throw PrivmxDriverCryptoException("Decrypt AES-256-ECB: Decryption finalization failed");
        }
        buf_len += final_len;
        EVP_CIPHER_CTX_cleanup(raw_ctx);
        return Bytes(buf, buf+buf_len);
    } else if (opt.cipher == SymAlg::Aes256Gcm) {
        throw PrivmxDriverCryptoException("Symmetric Decryption: AES-256-GCM not implemented");
    // } else if (opt.cipher == SymAlg::Aes256GcmAead) {
    } else {
        throw PrivmxDriverCryptoException("Symmetric Decryption: Unknown protocol");
    }
}

Bytes CryptoProviderFromOpenssl::derive(const KdfParams& opt, BytesView secretData)
{
    throw PrivmxDriverCryptoException("Key derivation function: NOT IMPLEMENTED");
}

std::shared_ptr<IPrivateKey> CryptoProviderFromOpenssl::generatePrivateKey(AsymAlg)
{
    throw PrivmxDriverCryptoException("generatePrivateKey: NOT IMPLEMENTED");
}

std::shared_ptr<IPrivateKey> CryptoProviderFromOpenssl::importPrivateKey(BytesView, KeyFormat, AsymAlg)
{
    throw PrivmxDriverCryptoException("importPrivateKey: NOT IMPLEMENTED");
}

std::shared_ptr<IPublicKey> CryptoProviderFromOpenssl::importPublicKey(BytesView, KeyFormat, AsymAlg)
{
    throw PrivmxDriverCryptoException("importPublicKey: NOT IMPLEMENTED");
}
std::shared_ptr<IExtKey> CryptoProviderFromOpenssl::extKeyFromSeed(BytesView seed, AsymAlg) {
    throw PrivmxDriverCryptoException("extKeyFromSeed: NOT IMPLEMENTED");
}
std::shared_ptr<IExtKey> CryptoProviderFromOpenssl::importExtKey(BytesView data, KeyFormat format, AsymAlg alg)
{
    throw PrivmxDriverCryptoException("importExtKey: NOT IMPLEMENTED");
}

} // namespace cryptoservice
} // privmx

