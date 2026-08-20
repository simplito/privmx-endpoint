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

#include "CoreTypes.hpp"
#include "CoreInterfaces.hpp"

#include "ECC.hpp"

namespace privmx {
namespace cryptoservice {
namespace ecc {

class PublicKey : public IPublicKey
{
public:
    static PublicKey fromDER(const std::string& der);
    static PublicKey fromBase58DER(const std::string& base58);
    PublicKey() = default;
    PublicKey(const ECC& key);
    bool operator==(const PublicKey& obj) const;
    bool operator!=(const PublicKey& obj) const;
    std::string toDER() const;
    std::string toBase58DER() const;
    std::string toBase58Address() const;
    bool verifyCompactSignatureWithHash(const std::string& message, const std::string& signature) const;
    const ECC& getEcc() const;
    bool verifyCompactSignature(const std::string& message, const std::string& signature) const;

    // static PublicKey fromDERb(BytesViewder der);
    // static PublicKey fromBase58DERb(BytesViewder base58);
    // std::string toDERb() const;
    // std::string toBase58DERb() const;
    // std::string toBase58AddressB() const;
    
    virtual bool verify(BytesView data, BytesView sig, SigScheme) const override;
    // virtual Bytes seal(BytesView data, const IPrivateKey* senderForSignature = nullptr) const override;
    virtual Bytes seal(BytesView data, const IPrivateKey& senderForSignature) const override;
    virtual Bytes export_(KeyFormat) const override;
    virtual void setSymProvider(std::shared_ptr<ISymCryptoProvider>) override;  

private:
    ECC _key;
    std::shared_ptr<ISymCryptoProvider> _provider;
};

inline const ECC& PublicKey::getEcc() const {
    return _key;
}

} // ecc
} // cryptoservice
} // privmx

#endif // _PRIVMXLIB_CRYPTOSERVICE_ECCIMPL_PUBLICKEY_HPP_