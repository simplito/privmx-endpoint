/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/


#include <emscripten.h>
#include <emscripten/val.h>
#include <emscripten/bind.h>

#include <privmx/crypto/emscripten/CryptoService.hpp>
#include <privmx/crypto/emscripten/Bindings.hpp>
#include <privmx/utils/Utils.hpp>
#include <privmx/crypto/CipherType.hpp>
#include <privmx/crypto/CryptoException.hpp>

using namespace privmx::crypto::emscriptenimpl;
using namespace emscripten;
using privmx::crypto::CipherType;
using privmx::crypto::CryptoException;

std::string CryptoService::randomBytes(const size_t length) const {
    val name = val::u8string("randomBytes");
    val params = val::object();
    params.set("length", length);
    return (
        Bindings::callJSSync<std::string>(name, params)
    );
}

std::string CryptoService::hmacSha1(const std::string& key, const std::string& data) const {
    return CryptoService::hmac("sha1", key, data);
}

std::string CryptoService::hmacSha256(const std::string& key, const std::string& data) const {
    return CryptoService::hmac("sha256", key, data);
}

std::string CryptoService::hmacSha512(const std::string& key, const std::string& data) const {
    return CryptoService::hmac("sha512", key, data);
}

std::string CryptoService::sha1(const std::string& data) const {
    val name = val::u8string("sha1");
    val params = val::object();
    params.set("data", typed_memory_view(data.size(), data.data()));
    return (
        Bindings::callJSSync<std::string>(name, params)
    );
}

std::string CryptoService::sha256(const std::string& data) const {
    val name = val::u8string("sha256");
    val params = val::object();
    params.set("data", typed_memory_view(data.size(), data.data()));
    return (
        Bindings::callJSSync<std::string>(name, params)
    );
}

std::string CryptoService::sha512(const std::string& data) const {
    val name = val::u8string("sha512");
    val params = val::object();
    params.set("data", typed_memory_view(data.size(), data.data()));
    return (
        Bindings::callJSSync<std::string>(name, params)
    );
}

std::string CryptoService::ripemd160(const std::string& data) const {
    val name = val::u8string("ripemd160");
    val params = val::object();
    params.set("data", typed_memory_view(data.size(), data.data()));
    return (
        Bindings::callJSSync<std::string>(name, params)
    );
}

std::string CryptoService::hash160(const std::string& data) const {
    val name = val::u8string("hash160");
    val params = val::object();
    params.set("data", typed_memory_view(data.size(), data.data()));
    return (
        Bindings::callJSSync<std::string>(name, params)
    );
}

std::string CryptoService::aes256EcbEncrypt(const std::string& data, const std::string& key) const {
    val name = val::u8string("aes256EcbEncrypt");
    val params = val::object();
    params.set("data", typed_memory_view(data.size(), data.data()));
    params.set("key", typed_memory_view(key.size(), key.data()));
    return (
        Bindings::callJSSync<std::string>(name, params)
    );
}

std::string CryptoService::aes256EcbDecrypt(const std::string& data, const std::string& key) const {
    val name = val::u8string("aes256EcbDecrypt");
    val params = val::object();
    params.set("data", typed_memory_view(data.size(), data.data()));
    params.set("key", typed_memory_view(key.size(), key.data()));
    return (
        Bindings::callJSSync<std::string>(name, params)
    );
}

std::string CryptoService::aes256CbcNoPadEncrypt(const std::string& data, const std::string& key, const std::string& iv) const {
    val name = val::u8string("aes256CbcNoPadEncrypt");
    val params = val::object();
    params.set("data", typed_memory_view(data.size(), data.data()));
    params.set("key", typed_memory_view(key.size(), key.data()));
    params.set("iv", typed_memory_view(iv.size(), iv.data()));
    return (
        Bindings::callJSSync<std::string>(name, params)
    );
}

std::string CryptoService::aes256CbcNoPadDecrypt(const std::string& data, const std::string& key, const std::string& iv) const {
    val name = val::u8string("aes256CbcNoPadDecrypt");
    val params = val::object();
    params.set("data", typed_memory_view(data.size(), data.data()));
    params.set("key", typed_memory_view(key.size(), key.data()));
    params.set("iv", typed_memory_view(iv.size(), iv.data()));
    return (
        Bindings::callJSSync<std::string>(name, params)
    );
}

std::string CryptoService::aes256CbcPkcs7Encrypt(const std::string& data, const std::string& key, const std::string& iv) const {
    val name = val::u8string("aes256CbcPkcs7Encrypt");
    val params = val::object();
    params.set("data", typed_memory_view(data.size(), data.data()));
    params.set("key", typed_memory_view(key.size(), key.data()));
    params.set("iv", typed_memory_view(iv.size(), iv.data()));
    return (
        Bindings::callJSSync<std::string>(name, params)
    );
}

std::string CryptoService::aes256CbcPkcs7Decrypt(const std::string& data, const std::string& key, const std::string& iv) const {
    val name = val::u8string("aes256CbcPkcs7Decrypt");
    val params = val::object();
    params.set("data", typed_memory_view(data.size(), data.data()));
    params.set("key", typed_memory_view(key.size(), key.data()));
    params.set("iv", typed_memory_view(iv.size(), iv.data()));
    return (
        Bindings::callJSSync<std::string>(name, params)
    );
}

std::string CryptoService::prf_tls12(const std::string& key, const std::string& seed, size_t length) const {
    val name = val::u8string("prf_tls12");
    val params = val::object();
    params.set("key", typed_memory_view(key.size(), key.data()));
    params.set("seed", typed_memory_view(seed.size(), seed.data()));
    params.set("length", length);
    return (
        Bindings::callJSSync<std::string>(name, params)
    );
}

std::string CryptoService::kdf(size_t length, const std::string& key, const std::string& label) const {
    val name = val::u8string("kdf");
    val params = val::object();
    params.set("length", length);
    params.set("key", typed_memory_view(key.size(), key.data()));
    params.set("label", label);
    return (
        Bindings::callJSSync<std::string>(name, params)
    );    
}

std::string CryptoService::generateIv(const std::string& key, Poco::Int32 idx) const {
    return hmacSha256(key, "iv" + std::to_string(idx)).substr(0, 16);
}

std::tuple<std::string, std::string> CryptoService::getKEM(const std::string& key, size_t kelen, size_t kmlen) const {
    std::string kEM = kdf(kelen + kmlen, key, "key expansion");
    return make_tuple(kEM.substr(0, kelen), kEM.substr(kelen));
}

std::string CryptoService::aes256CbcHmac256Encrypt(std::string data, const std::string& key32, std::string iv, size_t taglen) const {
    val name = val::u8string("aes256CbcHmac256Encrypt");
    val params = val::object();
    params.set("data", typed_memory_view(data.size(), data.data()));
    params.set("key", typed_memory_view(key32.size(), key32.data()));
    params.set("iv", typed_memory_view(iv.size(), iv.data()));
    params.set("taglen", taglen);
    return (
        Bindings::callJSSync<std::string>(name, params)
    );  
}

std::string CryptoService::aes256CbcHmac256Decrypt(std::string data, const std::string& key32, size_t taglen) const {
    val name = val::u8string("aes256CbcHmac256Decrypt");
    val params = val::object();
    emscripten::val data_view{typed_memory_view<char>(data.size(), data.c_str())};
    emscripten::val key_view{typed_memory_view<char>(key32.size(), key32.data())};
    params.set("data", data_view);
    params.set("key", key_view);
    params.set("taglen", val((int)taglen));
    return (
        Bindings::callJSSync<std::string>(name, params)
    );  
}

std::string CryptoService::ctAes256CbcPkcs7NoIv(const std::string& data, const std::string& key, const std::string& iv) const {
    return CipherType::AES_256_CBC_PKCS7_NO_IV + aes256CbcPkcs7Encrypt(data, key, iv);
}

std::string CryptoService::ctAes256CbcPkcs7WithIv(const std::string& data, const std::string& key, const std::string& iv) const {
    return CipherType::AES_256_CBC_PKCS7_WITH_IV + iv + aes256CbcPkcs7Encrypt(data, key, iv);
}

std::string CryptoService::ctAes256CbcPkcs7WithIvAndHmacSha256(const std::string& data, const std::string& key, const std::string& iv, size_t taglen) const {
    return CipherType::AES_256_CBC_PKCS7_WITH_IV_AND_HMAC_SHA256 + aes256CbcHmac256Encrypt(data, key, iv, taglen);
}

std::string CryptoService::ctDecrypt(const std::string& data, const std::string& key32, const std::string& iv16, size_t taglen, [[maybe_unused]] const std::string& key16) const {
    if (key32.length() != 32) {
        throw DecryptInvalidKeyLengthException("required: 32, received: " + std::to_string(key32.length()));
    }
    switch (data[0]) {
        case CipherType::AES_256_CBC_PKCS7_NO_IV:
            if (iv16.empty()) {
                throw MissingIvException();
            }
            return aes256CbcPkcs7Decrypt(data.substr(1), key32, iv16);
        case CipherType::AES_256_CBC_PKCS7_WITH_IV:
            return aes256CbcPkcs7Decrypt(data.substr(17), key32, data.substr(1, 16));
        case CipherType::XTEA_ECB_PKCS7:
            throw NotImplementedException();
        case CipherType::AES_256_CBC_PKCS7_WITH_IV_AND_HMAC_SHA256:
            return aes256CbcHmac256Decrypt(data.substr(1), key32, taglen);
    }
    throw UnknownDecryptionTypeException(std::to_string(data[0]));
}

std::string CryptoService::pbkdf2(const std::string& password, const std::string& salt, const int32_t rounds, const size_t length, const std::string& hash) const {
    val name = val::u8string("pbkdf2");
    val params = val::object();
    params.set("password", password);
    params.set("salt", salt);
    params.set("rounds", rounds);
    params.set("length", length);
    params.set("hash", hash);
    return (
        Bindings::callJSSync<std::string>(name, params)
    );  
}

std::string CryptoService::hmac(const std::string& engine, const std::string& key, const std::string& data) const {
    val name = val::u8string("hmac");
    val params = val::object();
    params.set("key", typed_memory_view(key.size(), key.data()));
    params.set("data", typed_memory_view(data.size(), data.data()));
    params.set("engine", engine);
    return (
        Bindings::callJSSync<std::string>(name, params)
    );
}
