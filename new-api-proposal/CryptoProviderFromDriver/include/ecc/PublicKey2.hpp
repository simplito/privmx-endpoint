/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTOSERVICE_ECC_PUBLICKEY2_HPP_
#define _PRIVMXLIB_CRYPTOSERVICE_ECC_PUBLICKEY2_HPP_

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
// #include "PublicKey2.hpp"
// #include "PrivateKey2.hpp"

namespace privmx {
namespace cryptoservice {
namespace ecc {

class PrivateKey2;

class PublicKey2 : public IPublicKey
{
public:
    using evp_pkey_unique_ptr = std::unique_ptr<EVP_PKEY, std::function<decltype(EVP_PKEY_free)>>;
    using evp_pkey_ctx_unique_ptr = std::unique_ptr<EVP_PKEY_CTX, std::function<decltype(EVP_PKEY_CTX_free)>>;
    // using ossl_param_unique_ptr = std::unique_ptr<OSSL_PARAM, std::function<decltype(OSSL_PARAM_clear_free)>>;
    using ossl_param_unique_ptr = std::unique_ptr<OSSL_PARAM, std::function<decltype(OSSL_PARAM_free)>>;
    using ossl_param_bld_unique_ptr = std::unique_ptr<OSSL_PARAM_BLD, std::function<decltype(OSSL_PARAM_BLD_free)>>;
    using bignum_unique_ptr = std::unique_ptr<BIGNUM, std::function<decltype(BN_free)>>;
    using evp_md_ctx_unique_ptr = std::unique_ptr<EVP_MD_CTX, std::function<decltype(EVP_MD_CTX_free)>>;

    PublicKey2 (BytesView rawdata, std::shared_ptr<ISymCryptoProvider> p = nullptr);

    Bytes toRaw() const;

    EVP_PKEY* getRawKey() const;

    Bytes encrypt(BytesView data, const PrivateKey2& privForSignature) const;
    bool verify(BytesView data, BytesView signature) const;

// from IPublicKey
    virtual bool verify(BytesView data, BytesView sig, SigScheme) const override;
    // virtual Bytes seal(BytesView data, const IPrivateKey* senderForSignature = nullptr) const override;
    virtual Bytes seal(BytesView data, const IPrivateKey& senderForSignature) const override;
    virtual Bytes export_(KeyFormat) const override;
    virtual void setSymProvider(std::shared_ptr<ISymCryptoProvider>) override;  

private:
    Bytes eciesEncrypt(BytesView data, const PrivateKey2& private_key) const;

    evp_pkey_unique_ptr _evp_pkey;
    std::shared_ptr<ISymCryptoProvider> _provider;
};

} // ecc
} // cryptoservice
} // privmx

#endif // _PRIVMXLIB_CRYPTOSERVICE_ECC_PUBLICKEY2_HPP_