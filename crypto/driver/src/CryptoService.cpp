#include <privmx/crypto/driver/CryptoService.hpp>

using namespace privmx::crypto;

#include <memory>
#include <functional>
#include <Poco/ByteOrder.h>

#include <privmx/drv/crypto.h>

#include <privmx/crypto/CipherType.hpp>
#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/CryptoException.hpp>

using namespace privmx;
using namespace privmx::crypto;
using namespace std;
using Poco::ByteOrder;
using Poco::UInt32;

string driverimpl::CryptoService::randomBytes(size_t length) const {
    string result(length, 0);
    int status = privmxDrvCrypto_randomBytes(result.data(), result.size());
    if (status != 0) {
        throw PrivmxDriverCryptoException("randomBytes: " + to_string(status));
    }
    return result;
}

string driverimpl::CryptoService::hmacSha1(const string& key, const string& data) const {
    char* out;
    unsigned int outlen;
    int status = privmxDrvCrypto_hmac(key.data(), key.size(), data.data(), data.size(), "SHA1", &out, &outlen);
    if (status != 0) {
        throw PrivmxDriverCryptoException("hmacSha1: " + to_string(status));
    }
    string res(out, outlen);
    privmxDrvCrypto_freeMem(out);
    return res;
}

string driverimpl::CryptoService::hmacSha256(const string& key, const string& data) const {
    char* out;
    unsigned int outlen;
    int status = privmxDrvCrypto_hmac(key.data(), key.size(), data.data(), data.size(), "SHA256", &out, &outlen);
    if (status != 0) {
        throw PrivmxDriverCryptoException("hmacSha256: " + to_string(status));
    }
    string res(out, outlen);
    privmxDrvCrypto_freeMem(out);
    return res;
}

string driverimpl::CryptoService::hmacSha512(const string& key, const string& data) const {
    char* out;
    unsigned int outlen;
    int status = privmxDrvCrypto_hmac(key.data(), key.size(), data.data(), data.size(), "SHA512", &out, &outlen);
    if (status != 0) {
        throw PrivmxDriverCryptoException("hmacSha512: " + to_string(status));
    }
    string res(out, outlen);
    privmxDrvCrypto_freeMem(out);
    return res;
}

string driverimpl::CryptoService::sha1(const string& data) const {
    char* out;
    unsigned int outlen;
    int status = privmxDrvCrypto_md(data.data(), data.size(), "SHA1", &out, &outlen);
    if (status != 0) {
        throw PrivmxDriverCryptoException("sha1: " + to_string(status));
    }
    string res(out, outlen);
    privmxDrvCrypto_freeMem(out);
    return res;
}

string driverimpl::CryptoService::sha256(const string& data) const {
    char* out;
    unsigned int outlen;
    int status = privmxDrvCrypto_md(data.data(), data.size(), "SHA256", &out, &outlen);
    if (status != 0) {
        throw PrivmxDriverCryptoException("sha256: " + to_string(status));
    }
    string res(out, outlen);
    privmxDrvCrypto_freeMem(out);
    return res;
}

string driverimpl::CryptoService::sha512(const string& data) const {
    char* out;
    unsigned int outlen;
    int status = privmxDrvCrypto_md(data.data(), data.size(), "SHA512", &out, &outlen);
    if (status != 0) {
        throw PrivmxDriverCryptoException("sha512: " + to_string(status));
    }
    string res(out, outlen);
    privmxDrvCrypto_freeMem(out);
    return res;
}

string driverimpl::CryptoService::ripemd160(const string& data) const {
    char* out;
    unsigned int outlen;
    int status = privmxDrvCrypto_md(data.data(), data.size(), "RIPEMD160", &out, &outlen);
    if (status != 0) {
        throw PrivmxDriverCryptoException("ripemd160: " + to_string(status));
    }
    string res(out, outlen);
    privmxDrvCrypto_freeMem(out);
    return res;
}

string driverimpl::CryptoService::hash160(const string& data) const {
    string data_sha256 = sha256(data);
    return ripemd160(data_sha256);
}

string driverimpl::CryptoService::aes256EcbEncrypt(const string& data, const string& key) const {
    char* out;
    unsigned int outlen;
    int status = privmxDrvCrypto_aesEncrypt(key.data(), NULL, data.data(), data.size(), "AES-256-ECB-NOPAD", &out, &outlen);
    if (status != 0) {
        throw PrivmxDriverCryptoException("aes256EcbEncrypt: " + to_string(status));
    }
    string res(out, outlen);
    privmxDrvCrypto_freeMem(out);
    return res;
}

string driverimpl::CryptoService::aes256EcbDecrypt(const string& data, const string& key) const {
    char* out;
    unsigned int outlen;
    int status = privmxDrvCrypto_aesDecrypt(key.data(), NULL, data.data(), data.size(), "AES-256-ECB-NOPAD", &out, &outlen);
    if (status != 0) {
        throw PrivmxDriverCryptoException("aes256EcbDecrypt: " + to_string(status));
    }
    string res(out, outlen);
    privmxDrvCrypto_freeMem(out);
    return res;
}

string driverimpl::CryptoService::aes256CbcPkcs7Encrypt(const string& data, const std::string& key, const std::string& iv) const {
    char* out;
    unsigned int outlen;
    int status = privmxDrvCrypto_aesEncrypt(key.data(), iv.data(), data.data(), data.size(), "AES-256-CBC", &out, &outlen);
    if (status != 0) {
        throw PrivmxDriverCryptoException("aes256CbcPkcs7Encrypt: " + to_string(status));
    }
    string res(out, outlen);
    privmxDrvCrypto_freeMem(out);
    return res;
}

string driverimpl::CryptoService::aes256CbcPkcs7Decrypt(const string& data, const std::string& key, const std::string& iv) const {
    char* out;
    unsigned int outlen;
    int status = privmxDrvCrypto_aesDecrypt(key.data(), iv.data(), data.data(), data.size(), "AES-256-CBC", &out, &outlen);
    if (status != 0) {
        throw PrivmxDriverCryptoException("aes256CbcPkcs7Decrypt: " + to_string(status));
    }
    string res(out, outlen);
    privmxDrvCrypto_freeMem(out);
    return res;
}

string driverimpl::CryptoService::aes256CbcNoPadEncrypt(const string& data, const std::string& key, const std::string& iv) const {
    char* out;
    unsigned int outlen;
    int status = privmxDrvCrypto_aesEncrypt(key.data(), iv.data(), data.data(), data.size(), "AES-256-CBC-NOPAD", &out, &outlen);
    if (status != 0) {
        throw PrivmxDriverCryptoException("aes256CbcNoPadEncrypt: " + to_string(status));
    }
    string res(out, outlen);
    privmxDrvCrypto_freeMem(out);
    return res;
}

string driverimpl::CryptoService::aes256CbcNoPadDecrypt(const string& data, const std::string& key, const std::string& iv) const {
    char* out;
    unsigned int outlen;
    int status = privmxDrvCrypto_aesDecrypt(key.data(), iv.data(), data.data(), data.size(), "AES-256-CBC-NOPAD", &out, &outlen);
    if (status != 0) {
        throw PrivmxDriverCryptoException("aes256CbcNoPadDecrypt: " + to_string(status));
    }
    string res(out, outlen);
    privmxDrvCrypto_freeMem(out);
    return res;
}


string driverimpl::CryptoService::prf_tls12(const string& key, const string& seed, size_t length) const {
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

string driverimpl::CryptoService::kdf(size_t length, const string& key, const string& label) const {
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

string driverimpl::CryptoService::generateIv(const string& key, Poco::Int32 idx) const {
    return hmacSha256(key, "iv" + to_string(idx)).substr(0, 16);
}

tuple<string, string> driverimpl::CryptoService::getKEM(const string& key, size_t kelen, size_t kmlen) const {
    string kEM = kdf(kelen + kmlen, key, "key expansion");
    return make_tuple(kEM.substr(0, kelen), kEM.substr(kelen));
}

string driverimpl::CryptoService::aes256CbcHmac256Encrypt(string data, const string& key32, string iv, size_t taglen) const {
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

string driverimpl::CryptoService::aes256CbcHmac256Decrypt(string data, const string& key32, size_t taglen) const {
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

string driverimpl::CryptoService::ctAes256CbcPkcs7NoIv(const string& data, const string& key, const string& iv) const {
    return CipherType::AES_256_CBC_PKCS7_NO_IV + aes256CbcPkcs7Encrypt(data, key, iv);
}

string driverimpl::CryptoService::ctAes256CbcPkcs7WithIv(const string& data, const string& key, const string& iv) const {
    return CipherType::AES_256_CBC_PKCS7_WITH_IV + iv + aes256CbcPkcs7Encrypt(data, key, iv);
}

string driverimpl::CryptoService::ctAes256CbcPkcs7WithIvAndHmacSha256(const string& data, const string& key, const string& iv, size_t taglen) const {
    return CipherType::AES_256_CBC_PKCS7_WITH_IV_AND_HMAC_SHA256 + aes256CbcHmac256Encrypt(data, key, iv, taglen);
}

string driverimpl::CryptoService::ctDecrypt(const string& data, const string& key32, const string& iv16, size_t taglen, [[maybe_unused]] const string& key16) const {
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

std::string driverimpl::CryptoService::pbkdf2(const std::string& password, const std::string& salt, const int32_t rounds, const size_t length, const std::string& hash) const {
    char* out;
    unsigned int outlen;
    int status = privmxDrvCrypto_pbkdf2(password.data(), password.size(), salt.data(), salt.size(), rounds, length, hash.data(), &out, &outlen);
    if (status != 0) {
        throw PrivmxDriverCryptoException("pbkdf2: " + to_string(status));
    }
    string res(out, outlen);
    privmxDrvCrypto_freeMem(out);
    return res;
}
