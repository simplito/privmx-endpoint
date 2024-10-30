#ifndef _PRIVMXLIB_ENDPOINT_CORE_DATAENCRYPTOR_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_DATAENCRYPTOR_HPP_

#include <string>
#include <tuple>
#include <optional>
#include <Poco/JSON/Parser.h>
#include <Pson/BinaryString.hpp>

#include <privmx/crypto/CryptoPrivmx.hpp>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/utils/TypedObject.hpp>

#include "privmx/endpoint/core/CoreTypes.hpp"
#include "privmx/endpoint/core/Types.hpp"
#include "privmx/endpoint/core/CoreException.hpp"

namespace privmx {
namespace endpoint {
namespace core {


class DataEncryptorUtil {
public:
    static bool checkSignedData(const Pson::BinaryString& dataSigned, const privmx::crypto::PublicKey& pubKey) {
        Pson::BinaryString signature, data_buf;
        std::tie(signature, data_buf) = extractSignAndDataBuff(dataSigned);
        return pubKey.verifyCompactSignatureWithHash(data_buf, signature);;
    }
    
    static bool checkSign(const Pson::BinaryString& data, const Pson::BinaryString signature, const privmx::crypto::PublicKey& pubKey) {
        return pubKey.verifyCompactSignatureWithHash(data, signature);
    }

    static bool hasSign(const Pson::BinaryString& data) {
        Pson::BinaryString plain = data;
        if (plain[0] == 1) {
            // Temporary Solution
            return true;
        }
        return false;
    }

    static std::tuple<Pson::BinaryString, Pson::BinaryString> extractSignAndDataBuff(const Pson::BinaryString& data) {
        Pson::BinaryString plain = data;
        if (plain[0] == 1) {
            size_t signature_length = reinterpret_cast<Poco::UInt8&>(plain[1]);
            auto signature = plain.substr(2, signature_length);
            auto data_buf = plain.substr(2 + signature_length);
            return {signature, data_buf};
        }
        throw UnsupportedTypeException();
    }
};

template<class T>
class DataEncryptorBase : public DataEncryptorUtil
{
public:
    virtual std::string encrypt(const T& data, const std::string& key) = 0; // base64
    virtual std::string encrypt(const T& data, const EncKey& encKey) = 0;
    
    std::string signAndEncrypt(const T& data, const privmx::crypto::PrivateKey& privKey, const std::string& key) {
        return utils::Base64::from(privmx::crypto::CryptoPrivmx::privmxEncrypt(privmx::crypto::CryptoPrivmx::privmxOptAesWithSignature(), sign(data, privKey), key));
    }
    std::string signAndEncrypt(const T& data, const privmx::crypto::PrivateKey& privKey, const core::EncKey& encKey) {
        return utils::Base64::from(privmx::crypto::CryptoPrivmx::privmxEncrypt(privmx::crypto::CryptoPrivmx::privmxOptAesWithSignature(), sign(data, privKey), encKey.key));
    }
    
    virtual Pson::BinaryString sign(const T& data, const privmx::crypto::PrivateKey& privKey) = 0; //
    virtual Pson::BinaryString getSign(const T& data, const privmx::crypto::PrivateKey& privKey) = 0;

    virtual T decrypt(const std::string& data, const std::string& key) = 0;
    virtual T decrypt(const std::string& data, const EncKey& encKey) = 0;

    virtual std::tuple<Pson::BinaryString, T, Pson::BinaryString> decryptAndGetSign(const std::string& data, const std::string& key) = 0;
    virtual std::tuple<Pson::BinaryString, T, Pson::BinaryString> decryptAndGetSign(const std::string& data, const EncKey& encKey) = 0;
};

template<class T = utils::TypedObject>
class DataEncryptor : public DataEncryptorBase<T>
{
public:
    std::string encrypt(const T& data, const std::string& key) {
        auto buffer = utils::Utils::stringify(data);
        return utils::Base64::from(privmx::crypto::CryptoPrivmx::privmxEncrypt(privmx::crypto::CryptoPrivmx::privmxOptAesWithSignature(), buffer, key));
    }
    std::string encrypt(const T& data, const EncKey& encKey) {
        return encrypt(data, encKey.key);
    }
    
    Pson::BinaryString sign(const T& data, const privmx::crypto::PrivateKey& privKey) {
        auto buffer = utils::Utils::stringify(data);
        auto signature = privKey.signToCompactSignatureWithHash(buffer);
        Pson::BinaryString plain;
        plain.push_back(1);
        plain.push_back(signature.length());
        plain.append(signature).append(buffer);
        return plain;
    }

    Pson::BinaryString getSign(const T& data, const privmx::crypto::PrivateKey& privKey) {
        auto buffer = utils::Utils::stringify(data);
        return Pson::BinaryString(privKey.signToCompactSignatureWithHash(buffer));
    }

    T decrypt(const std::string& data, const std::string& key) {
        auto decrypted = privmx::crypto::CryptoPrivmx::privmxDecrypt(true, utils::Base64::toString(data), key);
        Poco::JSON::Parser parser;
        auto var = parser.parse(decrypted);
        return utils::TypedObjectFactory::createObjectFromVar<T>(var);
    }
    T decrypt(const std::string& data, const EncKey& encKey) {
        return decrypt(data, encKey.key);
    }

    std::tuple<Pson::BinaryString, T, Pson::BinaryString> decryptAndGetSign(const std::string& data, const std::string& key) {
        Pson::BinaryString plain = privmx::crypto::CryptoPrivmx::privmxDecrypt(true, utils::Base64::toString(data), key);
        Pson::BinaryString signature, data_buf;
        std::tie(signature, data_buf) = this->extractSignAndDataBuff(plain);
        Poco::JSON::Parser parser;
        return {signature,  utils::TypedObjectFactory::createObjectFromVar<T>(parser.parse(data_buf)), data_buf};
    }
    std::tuple<Pson::BinaryString, T, Pson::BinaryString> decryptAndGetSign(const std::string& data, const EncKey& encKey) {
        return decryptAndGetSign(data, encKey.key);
    }
};


template<>
class DataEncryptor<Pson::BinaryString>  : public DataEncryptorBase<Pson::BinaryString>
{
public:
    std::string encrypt(const Pson::BinaryString& data, const std::string& key) {
        return utils::Base64::from(privmx::crypto::CryptoPrivmx::privmxEncrypt(privmx::crypto::CryptoPrivmx::privmxOptAesWithSignature(), data, key));
    }
    std::string encrypt(const Pson::BinaryString& data, const EncKey& encKey) {
        return encrypt(data, encKey.key);
    }

    Pson::BinaryString sign(const Pson::BinaryString& data, const privmx::crypto::PrivateKey& privKey) {
        auto signature = privKey.signToCompactSignatureWithHash(data);
        Pson::BinaryString plain;
        plain.push_back(1);
        plain.push_back(signature.length());
        plain.append(signature).append(data);
        return plain;
    }

    Pson::BinaryString getSign(const Pson::BinaryString& data, const privmx::crypto::PrivateKey& privKey) {
        return Pson::BinaryString(privKey.signToCompactSignatureWithHash(data));
    }

    
    Pson::BinaryString decrypt(const std::string& data, const std::string& key) {
        return Pson::BinaryString(privmx::crypto::CryptoPrivmx::privmxDecrypt(true, utils::Base64::toString(data), key));
    }
    Pson::BinaryString decrypt(const std::string& data, const EncKey& encKey) {
        return decrypt(data, encKey.key);
    }
    
    std::tuple<Pson::BinaryString, Pson::BinaryString, Pson::BinaryString> decryptAndGetSign(const std::string& data, const std::string& key) {
        Pson::BinaryString plain = privmx::crypto::CryptoPrivmx::privmxDecrypt(true, utils::Base64::toString(data), key);
        Pson::BinaryString signature, data_buf;
        std::tie(signature, data_buf) = this->extractSignAndDataBuff(plain);
        return {signature,  data_buf, data_buf};
    }
    std::tuple<Pson::BinaryString, Pson::BinaryString, Pson::BinaryString> decryptAndGetSign(const std::string& data, const EncKey& encKey) {
        return decryptAndGetSign(data, encKey.key);
    }
    
};

} // core
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_DATAENCRYPTOR_HPP_
