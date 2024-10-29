#include <privmx/crypto/openssl/CryptoService.hpp>

using namespace privmx::crypto;

#include <memory>
#include <functional>
#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ripemd.h>
#include <Poco/ByteOrder.h>
#include <Poco/Crypto/Crypto.h>
#include <Poco/Crypto/Cipher.h>
#include <Poco/Crypto/CipherFactory.h>
#include <Poco/Crypto/CipherKey.h>
#include <Poco/Crypto/DigestEngine.h>
#include <Poco/Crypto/OpenSSLInitializer.h>
#include <Poco/HMACEngine.h>
#include <Poco/RandomStream.h>
#include <Poco/SHA1Engine.h>

#include <privmx/crypto/CipherType.hpp>
#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/CryptoException.hpp>
#include <privmx/crypto/OpenSSLUtils.hpp>
#include <privmx/crypto/SHA256Engine.hpp>
#include <privmx/crypto/SHA512Engine.hpp>

using namespace privmx;
using namespace privmx::crypto;
using namespace std;
using namespace Poco::Crypto;
using Poco::RandomBuf;
using Poco::SHA1Engine;
using Poco::HMACEngine;
using Poco::UInt32;
using Poco::ByteOrder;

string opensslimpl::CryptoService::randomBytes(size_t length) const {
    RandomBuf random_buf;
    char buffer[length];
    random_buf.readFromDevice(buffer, length);
    return string(buffer, length);
}

string opensslimpl::CryptoService::hmacSha1(const string& key, const string& data) const {
    return hmac<SHA1Engine>(key, data);
}

string opensslimpl::CryptoService::hmacSha256(const string& key, const string& data) const {
    return hmac<SHA256Engine>(key, data);
}

string opensslimpl::CryptoService::hmacSha512(const string& key, const string& data) const {
    return hmac<SHA512Engine>(key, data);
}

string opensslimpl::CryptoService::sha1(const string& data) const {
    SHA1Engine sha1;
    sha1.update(data);
    Poco::DigestEngine::Digest digest = sha1.digest();
    return string(digest.begin(), digest.end());
}

string opensslimpl::CryptoService::sha256(const string& data) const {
    SHA256Engine sha256;
    sha256.update(data);
    Poco::DigestEngine::Digest digest = sha256.digest();
    return string(digest.begin(), digest.end());
}

string opensslimpl::CryptoService::sha512(const string& data) const {
    SHA512Engine sha512;
    sha512.update(data);
    Poco::DigestEngine::Digest digest = sha512.digest();
    return string(digest.begin(), digest.end());
}

string opensslimpl::CryptoService::ripemd160(const string& data) const {
    string result(20, 0);
    const unsigned char* d = reinterpret_cast<const unsigned char*>(data.data());
    size_t data_len = data.length();
    unsigned char* md = reinterpret_cast<unsigned char*>(result.data());
    if(RIPEMD160(d, data_len, md) == NULL) {
        OpenSSLUtils::handleErrors();
    }
    return result;
}

string opensslimpl::CryptoService::hash160(const string& data) const {
    string data_sha256 = sha256(data);
    return ripemd160(data_sha256);
}

string opensslimpl::CryptoService::aes256EcbEncrypt(const string& data, const string& key) const {
    unique_ptr<EVP_CIPHER_CTX, function<decltype(EVP_CIPHER_CTX_free)>> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    EVP_CIPHER_CTX* raw_ctx = ctx.get();
    if (raw_ctx == NULL) {
        OpenSSLUtils::handleErrors();
    }
    EVP_CIPHER_CTX_init(raw_ctx);
    const unsigned char* k = reinterpret_cast<const unsigned char*>(key.data());
    if (EVP_EncryptInit_ex(raw_ctx, EVP_aes_256_ecb(), NULL, k, NULL) != 1) {
        OpenSSLUtils::handleErrors();
    }
    if (EVP_CIPHER_CTX_set_padding(raw_ctx, 0) != 1) {
        OpenSSLUtils::handleErrors();
    }
    int data_len = data.length();
    unsigned char buf[data_len];
    int buf_len = 0;
    const unsigned char* d = reinterpret_cast<const unsigned char*>(data.data());
    if (EVP_EncryptUpdate(raw_ctx, buf, &buf_len, d, data_len) != 1) {
        OpenSSLUtils::handleErrors();
    }
    int final_len = 0;
    if (EVP_EncryptFinal_ex(raw_ctx, buf + buf_len, &final_len) != 1) {
        OpenSSLUtils::handleErrors();
    }
    buf_len += final_len;
    EVP_CIPHER_CTX_cleanup(raw_ctx);
    const char* buf_as_char = reinterpret_cast<char*>(buf);
    return string(buf_as_char, buf_len);
}

string opensslimpl::CryptoService::aes256EcbDecrypt(const string& data, const string& key) const {
    unique_ptr<EVP_CIPHER_CTX, function<decltype(EVP_CIPHER_CTX_free)>> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    EVP_CIPHER_CTX* raw_ctx = ctx.get();
    if (raw_ctx == NULL) {
        OpenSSLUtils::handleErrors();
    }
    EVP_CIPHER_CTX_init(raw_ctx);
    const unsigned char* k = reinterpret_cast<const unsigned char*>(key.data());
    if (EVP_DecryptInit_ex(raw_ctx, EVP_aes_256_ecb(), NULL, k, NULL) != 1) {
        OpenSSLUtils::handleErrors();
    }
    if (EVP_CIPHER_CTX_set_padding(raw_ctx, 0) != 1) {
        OpenSSLUtils::handleErrors();
    }
    int data_len = data.length();
    unsigned char buf[data_len];
    int buf_len = 0;
    const unsigned char* d = reinterpret_cast<const unsigned char*>(data.data());
    if (EVP_DecryptUpdate(raw_ctx, buf, &buf_len, d, data_len) != 1) {
        OpenSSLUtils::handleErrors();
    }
    int final_len = 0;
    if (EVP_DecryptFinal_ex(raw_ctx, buf + buf_len, &final_len) != 1) {
        OpenSSLUtils::handleErrors();
    }
    buf_len += final_len;
    EVP_CIPHER_CTX_cleanup(raw_ctx);
    const char* buf_as_char = reinterpret_cast<char*>(buf);
    return string(buf_as_char, buf_len);
}

string opensslimpl::CryptoService::aes256CbcPkcs7Encrypt(const string& data, const std::string& key, const std::string& iv) const {
    CipherFactory& factory = CipherFactory::defaultFactory();
    Cipher::ByteVec vkey(key.begin(), key.end());
    Cipher::ByteVec viv(iv.begin(), iv.end());
    CipherKey cipher_key("AES-256-CBC", vkey, viv);
    Cipher::Ptr cipher = factory.createCipher(cipher_key);
    return cipher->encryptString(data);
}

string opensslimpl::CryptoService::aes256CbcPkcs7Decrypt(const string& data, const std::string& key, const std::string& iv) const {
    CipherFactory& factory = CipherFactory::defaultFactory();
    Cipher::ByteVec vkey(key.begin(), key.end());
    Cipher::ByteVec viv(iv.begin(), iv.end());
    CipherKey cipher_key("AES-256-CBC", vkey, viv);
    Cipher::Ptr cipher = factory.createCipher(cipher_key);
    return cipher->decryptString(data);
}

string opensslimpl::CryptoService::aes256CbcNoPadEncrypt(const string& data, const std::string& key, const std::string& iv) const {
    unique_ptr<EVP_CIPHER_CTX, function<decltype(EVP_CIPHER_CTX_free)>> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    EVP_CIPHER_CTX* raw_ctx = ctx.get();
    if (raw_ctx == NULL) {
        OpenSSLUtils::handleErrors();
    }
    EVP_CIPHER_CTX_init(raw_ctx);
    const unsigned char* k = reinterpret_cast<const unsigned char*>(key.data());
    const unsigned char* i = reinterpret_cast<const unsigned char*>(iv.data());
    if (EVP_EncryptInit_ex(raw_ctx, EVP_aes_256_cbc(), NULL, k, i) != 1) {
        OpenSSLUtils::handleErrors();
    }
    if (EVP_CIPHER_CTX_set_padding(raw_ctx, 0) != 1) {
        OpenSSLUtils::handleErrors();
    }
    int data_len = data.length();
    unsigned char buf[data_len];
    int buf_len = 0;
    const unsigned char* d = reinterpret_cast<const unsigned char*>(data.data());
    if (EVP_EncryptUpdate(raw_ctx, buf, &buf_len, d, data_len) != 1) {
        OpenSSLUtils::handleErrors();
    }
    int final_len = 0;
    if (EVP_EncryptFinal_ex(raw_ctx, buf + buf_len, &final_len) != 1) {
        OpenSSLUtils::handleErrors();
    }
    buf_len += final_len;
    EVP_CIPHER_CTX_cleanup(raw_ctx);
    const char* buf_as_char = reinterpret_cast<char*>(buf);
    return string(buf_as_char, buf_len);
}

string opensslimpl::CryptoService::aes256CbcNoPadDecrypt(const string& data, const std::string& key, const std::string& iv) const {
    unique_ptr<EVP_CIPHER_CTX, function<decltype(EVP_CIPHER_CTX_free)>> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    EVP_CIPHER_CTX* raw_ctx = ctx.get();
    if (raw_ctx == NULL) {
        OpenSSLUtils::handleErrors();
    }
    EVP_CIPHER_CTX_init(raw_ctx);
    const unsigned char* k = reinterpret_cast<const unsigned char*>(key.data());
    const unsigned char* i = reinterpret_cast<const unsigned char*>(iv.data());
    if (EVP_DecryptInit_ex(raw_ctx, EVP_aes_256_cbc(), NULL, k, i) != 1) {
        OpenSSLUtils::handleErrors();
    }
    if (EVP_CIPHER_CTX_set_padding(raw_ctx, 0) != 1) {
        OpenSSLUtils::handleErrors();
    }
    int data_len = data.length();
    unsigned char buf[data_len];
    int buf_len = 0;
    const unsigned char* d = reinterpret_cast<const unsigned char*>(data.data());
    if (EVP_DecryptUpdate(raw_ctx, buf, &buf_len, d, data_len) != 1) {
        OpenSSLUtils::handleErrors();
    }
    int final_len = 0;
    if (EVP_DecryptFinal_ex(raw_ctx, buf + buf_len, &final_len) != 1) {
        OpenSSLUtils::handleErrors();
    }
    buf_len += final_len;
    EVP_CIPHER_CTX_cleanup(raw_ctx);
    const char* buf_as_char = reinterpret_cast<char*>(buf);
    return string(buf_as_char, buf_len);
}


string opensslimpl::CryptoService::prf_tls12(const string& key, const string& seed, size_t length) const {
    string a = seed;
    string result = "";
    while (result.length() < length) {
        a = hmacSha256(key, a);
        string tmp = a + seed;
        string d = hmacSha256(key, tmp);
        result.append(d);
    }
    return result.substr(0, length);
}

string opensslimpl::CryptoService::kdf(size_t length, const string& key, const string& label) const {
    UInt32 len = ByteOrder::toBigEndian((UInt32)length);
    string seed = label + '\0' + string((char *)&len, 4);
    string k = "";
    UInt32 i = 1;
    string result;
    while (result.length() < length) {
        string input = k;
        UInt32 count = ByteOrder::toBigEndian(i++);
        input.append((char *)&count, 4)
            .append(seed);
        k = hmacSha256(key, input);
        result.append(k);
    }
    return result.substr(0, length);
}

string opensslimpl::CryptoService::generateIv(const string& key, Poco::Int32 idx) const {
    return hmacSha256(key, "iv" + to_string(idx)).substr(0, 16);
}

tuple<string, string> opensslimpl::CryptoService::getKEM(const string& key, size_t kelen, size_t kmlen) const {
    string kEM = kdf(kelen + kmlen, key, "key expansion");
    return make_tuple(kEM.substr(0, kelen), kEM.substr(kelen));
}

string opensslimpl::CryptoService::aes256CbcHmac256Encrypt(string data, const string& key32, string iv, size_t taglen) const {
    string kE, kM;
    tie(kE, kM) = getKEM(key32);
    if (iv.empty()) {
        iv = hmacSha256(key32, data);
    }
    iv = iv.substr(0, 16);
    data = string(16, 0).append(data);
    string cipher = aes256CbcPkcs7Encrypt(data, kE, iv);
    string tag = hmacSha256(kM, cipher).substr(0, taglen);
    return cipher.append(tag);
}

string opensslimpl::CryptoService::aes256CbcHmac256Decrypt(string data, const string& key32, size_t taglen) const {
    string kE, kM;
    tie(kE, kM) = getKEM(key32);
    string tag = data.substr(data.length() - taglen);
    data = data.substr(0, data.length() - taglen);
    string rtag = hmacSha256(kM, data).substr(0, taglen);
    if (tag != rtag) {
        throw WrongMessageSecurityTagException();
    }
    string iv = data.substr(0, 16);
    data = data.substr(16);
    return aes256CbcPkcs7Decrypt(data, kE, iv);
}

string opensslimpl::CryptoService::ctAes256CbcPkcs7NoIv(const string& data, const string& key, const string& iv) const {
    return CipherType::AES_256_CBC_PKCS7_NO_IV + aes256CbcPkcs7Encrypt(data, key, iv);
}

string opensslimpl::CryptoService::ctAes256CbcPkcs7WithIv(const string& data, const string& key, const string& iv) const {
    return CipherType::AES_256_CBC_PKCS7_WITH_IV + iv + aes256CbcPkcs7Encrypt(data, key, iv);
}

string opensslimpl::CryptoService::ctAes256CbcPkcs7WithIvAndHmacSha256(const string& data, const string& key, const string& iv, size_t taglen) const {
    return CipherType::AES_256_CBC_PKCS7_WITH_IV_AND_HMAC_SHA256 + aes256CbcHmac256Encrypt(data, key, iv, taglen);
}

string opensslimpl::CryptoService::ctDecrypt(const string& data, const string& key32, const string& iv16, size_t taglen, [[maybe_unused]] const string& key16) const {
    if (key32.length() != 32) {
        throw DecryptInvalidKeyLengthException("required: 32, received: " + to_string(key32.length()));
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
    throw UnknownDecryptionTypeException(to_string(data[0]));
}

std::string opensslimpl::CryptoService::pbkdf2(const std::string& password, const std::string& salt, const int32_t rounds, const size_t length, const std::string& hash) const {
    if (hash != "SHA512") {
        throw UnsupportedHashAlgorithmException("'" + hash + "'");
    }
    string result(length, 0);
    const unsigned char *salt_as_uchars = reinterpret_cast<const unsigned char *>(salt.data());
    int salt_len = salt.length();
    unsigned char *result_as_uchars = reinterpret_cast<unsigned char *>(result.data());
    if (PKCS5_PBKDF2_HMAC(password.data(), password.length(), salt_as_uchars, salt_len, rounds, EVP_sha512(), length, result_as_uchars) != 1) {
        OpenSSLUtils::handleErrors();
    }
    return result;
}

template<class Engine>
string opensslimpl::CryptoService::hmac(const string& key, const string& data) {
    HMACEngine<Engine> hmac(key);
    hmac.update(data);
    Poco::DigestEngine::Digest digest = hmac.digest();
    return string(digest.begin(), digest.end());
}
