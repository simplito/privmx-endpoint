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

#include "CoreTypes.hpp"
#include "CoreInterfaces.hpp"
#include "ECC.hpp"
#include "PublicKey.hpp"
#include "PrivateKey.hpp"

namespace privmx {
namespace cryptoservice {
namespace ecc {

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
    // virtual Bytes open(BytesView sealed, const std::optional<IPublicKey>& pubOfSignature = std::nullopt) const override;
    virtual Bytes export_(KeyFormat) const override; 

// protected:
    static PrivateKey generateRandom();
    static PrivateKey fromWIF(const std::string& wif);
    std::string signToCompactSignature(const std::string& message) const;
    std::string signToCompactSignatureWithHash(const std::string& message) const;
    std::string toWIF() const;

    static PrivateKey fromWIFb(BytesView wif);
    Bytes toWIFb() const;

private:
    ECC _key;
    // std::shared_ptr<ISymCryptoProvider> _provider;
    static std::shared_ptr<ISymCryptoProvider> _provider;
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