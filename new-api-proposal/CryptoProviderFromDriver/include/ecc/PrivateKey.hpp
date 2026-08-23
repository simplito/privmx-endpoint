/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTOSERVICE_ECCIMPL_PRIVATEKEY_HPP_
#define _PRIVMXLIB_CRYPTOSERVICE_ECCIMPL_PRIVATEKEY_HPP_

// #include <functional>
#include <memory>
#include <string>
#include <optional>

#include <openssl/ec.h>

// from EciesEncryptor
#include <Poco/Dynamic/Var.h>
#include <Poco/JSON/Object.h>

#include "CoreTypes.hpp"
#include "CoreInterfaces.hpp"
#include "ECC.hpp"
#include "PublicKey.hpp"
#include "PrivateKey.hpp"

namespace privmx {
namespace cryptoservice {
namespace ecc {

class PublicKey;

class PrivateKey : public IPrivateKey
{
public:
    PrivateKey() {}
    PrivateKey(const ECC& key);
    PublicKey getPublicKey() const;
    std::string getPrivateEncKey() const;
    std::string derive(const PublicKey& public_key) const;
    ECC getEccKey() const;

    virtual Bytes sign(BytesView data, SigScheme) const override;
    virtual std::shared_ptr<IPublicKey> publicKey() const override;
    virtual Bytes deriveSharedSecret(const IPublicKey& publicKey) const override;  
    virtual Bytes open(BytesView sealed, const IPublicKey* expectedSender = nullptr) const override;  
    virtual Bytes export_(KeyFormat) const override; 

// protected:
    static PrivateKey generateRandom();
    static PrivateKey fromWIF(const std::string& wif);
    std::string signToCompactSignature(const std::string& message) const;
    std::string signToCompactSignatureWithHash(const std::string& message) const;
    std::string toWIF() const;

    static PrivateKey fromWIFb(std::shared_ptr<IDigest> p, BytesView wif);
    Bytes toWIFb() const;
    Bytes deriveB(const PublicKey& public_key) const;

    virtual void setSymProvider(std::shared_ptr<ISymCryptoProvider>) override;  

// from EciesEncryptor class:
    Poco::JSON::Object::Ptr decryptObjectFromBase64(const std::string& cipher_base64, const std::optional<PublicKey>& pubOfSignature = std::nullopt) const;
    std::string decryptFromBase64(const std::string& cipher_base64, const std::optional<PublicKey>& pubOfSignature = std::nullopt) const;
    std::string decrypt(const std::string& cipher, const std::optional<PublicKey>& pubOfSignature = std::nullopt) const;
    std::string decryptV0(const PublicKey& pub, const std::string& cipher) const;

private:
    ECC _key;
    // static std::shared_ptr<ISymCryptoProvider> _provider;
    std::shared_ptr<ISymCryptoProvider> _provider;

// from ECIES class:
    std::string eciesDecrypt(const std::string& enc_buf, const PublicKey& public_key) const;
};

inline PublicKey PrivateKey::getPublicKey() const {
    return PublicKey(_key);
}

inline ECC PrivateKey::getEccKey() const {
    return _key;
}


} // ecc
} // cryptoservice
} // privmx

#endif // _PRIVMXLIB_CRYPTOSERVICE_ECCIMPL_PRIVATEKEY_HPP_