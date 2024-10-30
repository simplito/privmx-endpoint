#ifndef _PRIVMXLIB_CRYPTO_OPENSSL_CRYPTOSERVICE_HPP_
#define _PRIVMXLIB_CRYPTO_OPENSSL_CRYPTOSERVICE_HPP_

#include <privmx/crypto/CryptoService.hpp>

namespace privmx {
namespace crypto {
namespace opensslimpl {

class CryptoService : public privmx::crypto::CryptoService
{
public:
    virtual std::string randomBytes(size_t length) const override;
    virtual std::string hmacSha1(const std::string& key, const std::string& data) const override;
    virtual std::string hmacSha256(const std::string& key, const std::string& data) const override;
    virtual std::string hmacSha512(const std::string& key, const std::string& data) const override;
    virtual std::string sha1(const std::string& data) const override;
    virtual std::string sha256(const std::string& data) const override;
    virtual std::string sha512(const std::string& data) const override;
    virtual std::string ripemd160(const std::string& data) const override;
    virtual std::string hash160(const std::string& data) const override;
    virtual std::string aes256EcbEncrypt(const std::string& data, const std::string& key) const override;
    virtual std::string aes256EcbDecrypt(const std::string& data, const std::string& key) const override;
    virtual std::string aes256CbcPkcs7Encrypt(const std::string& data, const std::string& key, const std::string& iv) const override;
    virtual std::string aes256CbcPkcs7Decrypt(const std::string& data, const std::string& key, const std::string& iv) const override;
    virtual std::string aes256CbcNoPadEncrypt(const std::string& data, const std::string& key, const std::string& iv) const override;
    virtual std::string aes256CbcNoPadDecrypt(const std::string& data, const std::string& key, const std::string& iv) const override;
    virtual std::string prf_tls12(const std::string& key, const std::string& seed, size_t length) const override;
    virtual std::string kdf(size_t length, const std::string& key, const std::string& label) const override;
    virtual std::string generateIv(const std::string& key, Poco::Int32 idx) const override;
    virtual std::tuple<std::string, std::string> getKEM(const std::string& key, size_t kelen = 32, size_t kmlen = 32) const override;
    virtual std::string aes256CbcHmac256Encrypt(std::string data, const std::string& key32, std::string iv, size_t taglen = 16) const override;
    virtual std::string aes256CbcHmac256Decrypt(std::string data, const std::string& key32, size_t taglen = 16) const override;
    virtual std::string ctAes256CbcPkcs7NoIv(const std::string& data, const std::string& key, const std::string& iv) const override;
    virtual std::string ctAes256CbcPkcs7WithIv(const std::string& data, const std::string& key, const std::string& iv) const override;
    virtual std::string ctAes256CbcPkcs7WithIvAndHmacSha256(const std::string& data, const std::string& key, const std::string& iv, size_t taglen = 16) const override;
    virtual std::string ctDecrypt(const std::string& data, const std::string& key32, const std::string& iv16, size_t taglen = 16, const std::string& key16 = std::string()) const override;
    virtual std::string pbkdf2(const std::string& password, const std::string& salt, const int32_t rounds, const size_t length, const std::string& hash) const override;

private:
    template<class Engine>
    static std::string hmac(const std::string& key, const std::string& data);
};

} // opensslimpl
} // crypto
} // privmx

#endif // _PRIVMXLIB_CRYPTO_OPENSSL_CRYPTOSERVICE_HPP_
