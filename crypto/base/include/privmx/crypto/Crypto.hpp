#ifndef _PRIVMXLIB_CRYPTO_CRYPTO_HPP_
#define _PRIVMXLIB_CRYPTO_CRYPTO_HPP_

#include <tuple>
#include <string>
#include <Poco/Types.h>

#include <privmx/crypto/CryptoEnv.hpp>

namespace privmx {
namespace crypto {

class Crypto
{
public:
    static std::string randomBytes(size_t length);
    static std::string hmacSha1(const std::string& key, const std::string& data);
    static std::string hmacSha256(const std::string& key, const std::string& data);
    static std::string hmacSha512(const std::string& key, const std::string& data);
    static std::string sha1(const std::string& data);
    static std::string sha256(const std::string& data);
    static std::string sha512(const std::string& data);
    static std::string ripemd160(const std::string& data);
    static std::string hash160(const std::string& data);
    static std::string aes256EcbEncrypt(const std::string& data, const std::string& key);
    static std::string aes256EcbDecrypt(const std::string& data, const std::string& key);
    static std::string aes256CbcPkcs7Encrypt(const std::string& data, const std::string& key, const std::string& iv);
    static std::string aes256CbcPkcs7Decrypt(const std::string& data, const std::string& key, const std::string& iv);
    static std::string aes256CbcNoPadEncrypt(const std::string& data, const std::string& key, const std::string& iv);
    static std::string aes256CbcNoPadDecrypt(const std::string& data, const std::string& key, const std::string& iv);
    static std::string prf_tls12(const std::string& key, const std::string& seed, size_t length);
    static std::string pbkdf2(const std::string& password, const std::string& salt, size_t rounds, size_t length, const std::string& algorithm);
    static std::string kdf(size_t length, const std::string& key, const std::string& label);
    static std::string generateIv(const std::string& key, Poco::Int32 idx);
    static std::tuple<std::string, std::string> getKEM(const std::string& key, size_t kelen = 32, size_t kmlen = 32);
    static std::string aes256CbcHmac256Encrypt(std::string data, const std::string& key32, std::string iv = std::string(), size_t taglen = 16);
    static std::string aes256CbcHmac256Decrypt(std::string data, const std::string& key32, size_t taglen = 16);
    static std::string ctAes256CbcPkcs7NoIv(const std::string& data, const std::string& key, const std::string& iv);
    static std::string ctAes256CbcPkcs7WithIv(const std::string& data, const std::string& key, const std::string& iv);
    static std::string ctAes256CbcPkcs7WithIvAndHmacSha256(const std::string& data, const std::string& key, const std::string& iv, size_t taglen = 16);
    static std::string ctDecrypt(const std::string& data, const std::string& key32, const std::string& iv16, size_t taglen = 16, const std::string& key16 = std::string());
};

inline std::string Crypto::randomBytes(size_t length) {
    auto crypto_service = CryptoEnv::getEnv()->getCryptoService();
    return crypto_service->randomBytes(length);
}

inline std::string Crypto::hmacSha1(const std::string& key, const std::string& data) {
    auto crypto_service = CryptoEnv::getEnv()->getCryptoService();
    return crypto_service->hmacSha1(key, data);
}

inline std::string Crypto::hmacSha256(const std::string& key, const std::string& data) {
    auto crypto_service = CryptoEnv::getEnv()->getCryptoService();
    return crypto_service->hmacSha256(key, data);
}

inline std::string Crypto::hmacSha512(const std::string& key, const std::string& data) {
    auto crypto_service = CryptoEnv::getEnv()->getCryptoService();
    return crypto_service->hmacSha512(key, data);
}

inline std::string Crypto::sha1(const std::string& data) {
    auto crypto_service = CryptoEnv::getEnv()->getCryptoService();
    return crypto_service->sha1(data);
}

inline std::string Crypto::sha256(const std::string& data) {
    auto crypto_service = CryptoEnv::getEnv()->getCryptoService();
    return crypto_service->sha256(data);
}

inline std::string Crypto::sha512(const std::string& data) {
    auto crypto_service = CryptoEnv::getEnv()->getCryptoService();
    return crypto_service->sha512(data);
}

inline std::string Crypto::ripemd160(const std::string& data) {
    auto crypto_service = CryptoEnv::getEnv()->getCryptoService();
    return crypto_service->ripemd160(data);
}

inline std::string Crypto::hash160(const std::string& data) {
    auto crypto_service = CryptoEnv::getEnv()->getCryptoService();
    return crypto_service->hash160(data);
}

inline std::string Crypto::aes256EcbEncrypt(const std::string& data, const std::string& key) {
    auto crypto_service = CryptoEnv::getEnv()->getCryptoService();
    return crypto_service->aes256EcbEncrypt(data, key);
}

inline std::string Crypto::aes256EcbDecrypt(const std::string& data, const std::string& key) {
    auto crypto_service = CryptoEnv::getEnv()->getCryptoService();
    return crypto_service->aes256EcbDecrypt(data, key);
}

inline std::string Crypto::aes256CbcPkcs7Encrypt(const std::string& data, const std::string& key, const std::string& iv) {
    auto crypto_service = CryptoEnv::getEnv()->getCryptoService();
    return crypto_service->aes256CbcPkcs7Encrypt(data, key, iv);
}

inline std::string Crypto::aes256CbcPkcs7Decrypt(const std::string& data, const std::string& key, const std::string& iv) {
    auto crypto_service = CryptoEnv::getEnv()->getCryptoService();
    return crypto_service->aes256CbcPkcs7Decrypt(data, key, iv);
}

inline std::string Crypto::aes256CbcNoPadEncrypt(const std::string& data, const std::string& key, const std::string& iv) {
    auto crypto_service = CryptoEnv::getEnv()->getCryptoService();
    return crypto_service->aes256CbcNoPadEncrypt(data, key, iv);
}

inline std::string Crypto::aes256CbcNoPadDecrypt(const std::string& data, const std::string& key, const std::string& iv) {
    auto crypto_service = CryptoEnv::getEnv()->getCryptoService();
    return crypto_service->aes256CbcNoPadDecrypt(data, key, iv);
}

inline std::string Crypto::prf_tls12(const std::string& key, const std::string& seed, size_t length) {
    auto crypto_service = CryptoEnv::getEnv()->getCryptoService();
    return crypto_service->prf_tls12(key, seed, length);
}

inline std::string Crypto::pbkdf2(const std::string& password, const std::string& salt, size_t rounds, size_t length, const std::string& algorithm) {
    auto crypto_service = CryptoEnv::getEnv()->getCryptoService();
    return crypto_service->pbkdf2(password, salt, rounds, length, algorithm);
}

inline std::string Crypto::kdf(size_t length, const std::string& key, const std::string& label) {
    auto crypto_service = CryptoEnv::getEnv()->getCryptoService();
    return crypto_service->kdf(length, key, label);
}

inline std::string Crypto::generateIv(const std::string& key, Poco::Int32 idx) {
    auto crypto_service = CryptoEnv::getEnv()->getCryptoService();
    return crypto_service->generateIv(key, idx);
}

inline std::tuple<std::string, std::string> Crypto::getKEM(const std::string& key, size_t kelen, size_t kmlen) {
    auto crypto_service = CryptoEnv::getEnv()->getCryptoService();
    return crypto_service->getKEM(key, kelen, kmlen);
}

inline std::string Crypto::aes256CbcHmac256Encrypt(std::string data, const std::string& key32, std::string iv, size_t taglen) {
    auto crypto_service = CryptoEnv::getEnv()->getCryptoService();
    return crypto_service->aes256CbcHmac256Encrypt(data, key32, iv, taglen);
}

inline std::string Crypto::aes256CbcHmac256Decrypt(std::string data, const std::string& key32, size_t taglen) {
    auto crypto_service = CryptoEnv::getEnv()->getCryptoService();
    return crypto_service->aes256CbcHmac256Decrypt(data, key32, taglen);
}

inline std::string Crypto::ctAes256CbcPkcs7NoIv(const std::string& data, const std::string& key, const std::string& iv) {
    auto crypto_service = CryptoEnv::getEnv()->getCryptoService();
    return crypto_service->ctAes256CbcPkcs7NoIv(data, key, iv);
}

inline std::string Crypto::ctAes256CbcPkcs7WithIv(const std::string& data, const std::string& key, const std::string& iv) {
    auto crypto_service = CryptoEnv::getEnv()->getCryptoService();
    return crypto_service->ctAes256CbcPkcs7WithIv(data, key, iv);
}

inline std::string Crypto::ctAes256CbcPkcs7WithIvAndHmacSha256(const std::string& data, const std::string& key, const std::string& iv, size_t taglen) {
    auto crypto_service = CryptoEnv::getEnv()->getCryptoService();
    return crypto_service->ctAes256CbcPkcs7WithIvAndHmacSha256(data, key, iv, taglen);
}

inline std::string Crypto::ctDecrypt(const std::string& data, const std::string& key32, const std::string& iv16, size_t taglen, const std::string& key16) {
    auto crypto_service = CryptoEnv::getEnv()->getCryptoService();
    return crypto_service->ctDecrypt(data, key32, iv16, taglen, key16);
}


} // crypto
} // privmx

#endif // _PRIVMXLIB_CRYPTO_CRYPTO_HPP_
