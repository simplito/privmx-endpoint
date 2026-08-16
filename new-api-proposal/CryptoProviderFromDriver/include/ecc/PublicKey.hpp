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
    PublicKey() = default;
    PublicKey(const ECC& key);
    bool operator==(const PublicKey& obj) const;
    bool operator!=(const PublicKey& obj) const;
    std::string toDER() const;
    std::string toBase58DER() const;
    std::string toBase58Address() const;
    bool verifyCompactSignatureWithHash(const std::string& message, const std::string& signature) const;
    const ECC& getEcc() const;

    virtual bool  verify(BytesView data, BytesView sig, SigScheme) const override;
    virtual Bytes seal(BytesView data, const IPrivateKey* senderForSignature = nullptr) const override;
    virtual Bytes export_(KeyFormat) const override;

protected:
    static PublicKey fromBase58DER(const std::string& base58);
    bool verifyCompactSignature(const std::string& message, const std::string& signature) const;

private:
    ECC _key;
    std::shared_ptr<ISymCryptoProvider> _provider;
};

inline const ECC& PublicKey::getEcc() const {
    return _key;
}

inline bool PublicKey::verify(BytesView data, BytesView sig, SigScheme) const {
    throw PrivmxDriverCryptoException("PublicKey::verify: NOT IMPLEMENTED");
}

inline Bytes PublicKey::seal(BytesView data, const IPrivateKey* senderForSignature) const {
    throw PrivmxDriverCryptoException("PublicKey::seal: NOT IMPLEMENTED");
}

inline Bytes PublicKey::export_(KeyFormat) const {
    throw PrivmxDriverCryptoException("PrivateKey::export_: NOT IMPLEMENTED");
}

} // ecc
} // cryptoservice
} // privmx

#endif // _PRIVMXLIB_CRYPTOSERVICE_ECCIMPL_PUBLICKEY_HPP_