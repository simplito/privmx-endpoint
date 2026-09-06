/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTOSERVICE_ECC_PRIVATEKEY2_HPP_
#define _PRIVMXLIB_CRYPTOSERVICE_ECC_PRIVATEKEY2_HPP_

// #include <functional>
#include <memory>
#include <string>
#include <optional>

#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/ec.h>

// // from EciesEncryptor
// #include <Poco/Dynamic/Var.h>
// #include <Poco/JSON/Object.h>

#include "CoreTypes.hpp"
#include "CoreInterfaces.hpp"
// #include "ECC.hpp"
// #include "PublicKey.hpp"
// #include "PrivateKey.hpp"

#include "PublicKey2.hpp"

namespace privmx {
namespace cryptoservice {
namespace ecc {

class PublicKey2;

class PrivateKey2 : public IPrivateKey
{
public:
    using evp_pkey_unique_ptr = std::unique_ptr<EVP_PKEY, std::function<decltype(EVP_PKEY_free)>>;
    using evp_pkey_ctx_unique_ptr = std::unique_ptr<EVP_PKEY_CTX, std::function<decltype(EVP_PKEY_CTX_free)>>;
    // using ossl_param_unique_ptr = std::unique_ptr<OSSL_PARAM, std::function<decltype(OSSL_PARAM_clear_free)>>;
    using ossl_param_unique_ptr = std::unique_ptr<OSSL_PARAM, std::function<decltype(OSSL_PARAM_free)>>;
    using ossl_param_bld_unique_ptr = std::unique_ptr<OSSL_PARAM_BLD, std::function<decltype(OSSL_PARAM_BLD_free)>>;
    using bignum_unique_ptr = std::unique_ptr<BIGNUM, std::function<decltype(BN_free)>>;
    // using evp_md_ctx_unique_ptr = std::unique_ptr<EVP_MD_CTX, std::function<decltype(EVP_MD_CTX_destroy)>>;
    using evp_md_ctx_unique_ptr = std::unique_ptr<EVP_MD_CTX, std::function<decltype(EVP_MD_CTX_free)>>;

    PrivateKey2 (std::shared_ptr<ISymCryptoProvider> p = nullptr);
    PrivateKey2 (BytesView rawdata, std::shared_ptr<ISymCryptoProvider> p = nullptr);

    PublicKey2 getPublicKey() const;

    Bytes toRaw() const;
    Bytes toRawPublicKey() const;

    Bytes sign(BytesView data) const;

// from IPrivateKey
    virtual Bytes sign(BytesView data, SigScheme) const override;
    virtual std::shared_ptr<IPublicKey> publicKey() const override;
    virtual Bytes deriveSharedSecret(const IPublicKey& publicKey) const override;  
    virtual Bytes open(BytesView sealed, const IPublicKey* expectedSender = nullptr) const override;  
    // Bytes open(BytesView sealed, const IPublicKey* expectedSender = nullptr) const;  
    virtual Bytes export_(KeyFormat) const override; 
    virtual void setSymProvider(std::shared_ptr<ISymCryptoProvider>) override;  

    Bytes derive(EVP_PKEY* peerkey) const;
    Bytes derive(const PublicKey2& peerkey) const;

    // Bytes decrypt(BytesView cipher, const std::optional<PublicKey2>& pubOfSignature = std::nullopt) const;
    Bytes decrypt(BytesView cipher, const PublicKey2 *pubOfSignature) const;
    Bytes decrypt(BytesView cipher) const;

private:
    Bytes eciesDecrypt(BytesView enc_buf, const PublicKey2& public_key) const;

    evp_pkey_unique_ptr _evp_pkey;
    std::shared_ptr<ISymCryptoProvider> _provider;
};


inline PublicKey2 PrivateKey2::getPublicKey() const {
    // return PublicKey(_key);
    // return PublicKey(_provider,_key);
    return PublicKey2(toRawPublicKey(), _provider);
}


} // ecc
} // cryptoservice
} // privmx

#endif // _PRIVMXLIB_CRYPTOSERVICE_ECC_PRIVATEKEY2_HPP_