/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTOSERVICE_ECCIMPL_PUBLICKEY_HPP_
#define _PRIVMXLIB_CRYPTOSERVICE_ECCIMPL_PUBLICKEY_HPP_

#include <functional>
#include <memory>
#include <string>
#include <openssl/bn.h>
#include <Poco/SharedPtr.h>

// from EciesEncryptor
#include <Poco/Dynamic/Var.h>
#include <Poco/JSON/Object.h>
// #include "PrivateKey.hpp"

#include "CoreTypes.hpp"
#include "CoreInterfaces.hpp"

#include "ECC.hpp"

namespace privmx {
namespace cryptoservice {
namespace ecc {

class PrivateKey;

class PublicKey : public IPublicKey
{
public:
    static PublicKey fromDER(const std::string& der);
    static PublicKey fromBase58DER(const std::string& base58);
    PublicKey() = default;
    PublicKey(const ECC& key);
    PublicKey(std::shared_ptr<ISymCryptoProvider> p); // new
    PublicKey(std::shared_ptr<ISymCryptoProvider> p, const ECC& key); // new
    bool operator==(const PublicKey& obj) const;
    bool operator!=(const PublicKey& obj) const;
    std::string toDER() const;
    std::string toBase58DER() const;
    std::string toBase58Address() const;
    bool verifyCompactSignatureWithHash(const std::string& message, const std::string& signature) const;
    const ECC& getEcc() const;
    bool verifyCompactSignature(const std::string& message, const std::string& signature) const;

    // // To do: implement the following methods to operate on Bytes and ViewBytes
    // static PublicKey fromDERb(BytesViewder der);
    // static PublicKey fromBase58DERb(BytesViewder base58);
    // std::string toDERb() const;
    // std::string toBase58DERb() const;
    // std::string toBase58AddressB() const;
    
    static PublicKey fromDER(std::shared_ptr<ISymCryptoProvider> p, BytesView der);
    static PublicKey fromBase58DER(std::shared_ptr<ISymCryptoProvider> p, BytesView base58);
    virtual bool verify(BytesView data, BytesView sig, SigScheme) const override;
    // virtual Bytes seal(BytesView data, const IPrivateKey* senderForSignature = nullptr) const override;
    virtual Bytes seal(BytesView data, const IPrivateKey& senderForSignature) const override;
    virtual Bytes export_(KeyFormat) const override;
    virtual void setSymProvider(std::shared_ptr<ISymCryptoProvider>) override;  

// from EciesEncryptor class:
    std::string encryptObjectToBase64(Poco::JSON::Object::Ptr data, const PrivateKey& privForSignature) const;
    std::string encryptToBase64(const std::string& data, const PrivateKey& privForSignature) const;
    std::string encrypt(const std::string& data, const PrivateKey& privForSignature) const;
// new variants:
    Bytes encrypt(BytesView data, const PrivateKey& privForSignature) const;

    Bytes toDERb() const;
    Bytes toBase58DERb() const;
    Bytes toBase58AddressB() const;
    bool verifyCompactSignatureWithHash(BytesView message, BytesView signature) const;
    bool verifyCompactSignature(BytesView message, BytesView signature) const;
private:
    ECC _key;
    std::shared_ptr<ISymCryptoProvider> _provider;

// from ECIES class:
    std::string eciesEncrypt(const std::string& data, const PrivateKey& private_key) const;
// new variants:
    Bytes eciesEncrypt(BytesView data, const PrivateKey& private_key) const;
};

inline const ECC& PublicKey::getEcc() const {
    return _key;
}

} // ecc
} // cryptoservice
} // privmx

#endif // _PRIVMXLIB_CRYPTOSERVICE_ECCIMPL_PUBLICKEY_HPP_