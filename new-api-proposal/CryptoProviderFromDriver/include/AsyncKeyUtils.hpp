/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTOSERVICE_ASYNCKEYUTILS_HPP_
#define _PRIVMXLIB_CRYPTOSERVICE_ASYNCKEYUTILS_HPP_

// #include <functional>
#include <memory>
#include <string>
#include <optional>
#include <map>

#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/ec.h>
#include <openssl/engine.h>

#include "CoreTypes.hpp"
#include "CoreInterfaces.hpp"

namespace privmx {
namespace cryptoservice {
// namespace ecc {

class AsyncKeyUtils 
{
public:
    using evp_pkey_unique_ptr = std::unique_ptr<EVP_PKEY, std::function<decltype(EVP_PKEY_free)>>;
    using evp_pkey_ctx_unique_ptr = std::unique_ptr<EVP_PKEY_CTX, std::function<decltype(EVP_PKEY_CTX_free)>>;
    // using ossl_param_unique_ptr = std::unique_ptr<OSSL_PARAM, std::function<decltype(OSSL_PARAM_clear_free)>>; // requires a higher version of OpenSSL library
    using ossl_param_unique_ptr = std::unique_ptr<OSSL_PARAM, std::function<decltype(OSSL_PARAM_free)>>;
    using ossl_param_bld_unique_ptr = std::unique_ptr<OSSL_PARAM_BLD, std::function<decltype(OSSL_PARAM_BLD_free)>>;
    using bignum_unique_ptr = std::unique_ptr<BIGNUM, std::function<decltype(BN_free)>>;
    // using evp_md_ctx_unique_ptr = std::unique_ptr<EVP_MD_CTX, std::function<decltype(EVP_MD_CTX_destroy)>>; // requires a higher version of OpenSSL library
    using evp_md_ctx_unique_ptr = std::unique_ptr<EVP_MD_CTX, std::function<decltype(EVP_MD_CTX_free)>>;

    using evp_signature_unique_ptr = std::unique_ptr<EVP_SIGNATURE, std::function<decltype(EVP_SIGNATURE_free)>>;

    // for public EC keys
    using ec_group_unique_ptr = std::unique_ptr<EC_GROUP, std::function<decltype(EC_GROUP_free)>>;
    using ec_point_unique_ptr = std::unique_ptr<EC_POINT, std::function<decltype(EC_POINT_free)>>;

    // for ECDSA 
    using ecdsa_sig_unique_ptr = std::unique_ptr<ECDSA_SIG, std::function<decltype(ECDSA_SIG_free)>>;


    // temporary - for testing only - TO REMOVE
    static void showParams(std::shared_ptr<EVP_PKEY> key);

    static std::shared_ptr<EVP_PKEY> getRandomKey(AsymAlg);
    static std::shared_ptr<EVP_PKEY> getKeyFromId(int id);
    static std::shared_ptr<EVP_PKEY> getKeyFromName(const char *name);
    static std::shared_ptr<EVP_PKEY> getKeyFromNameAndSeed(const char *name, BytesView seed);

    static Bytes toRaw(AsymAlg, std::shared_ptr<EVP_PKEY> key, bool includePrivate = true);
    static Bytes toRawP256(std::shared_ptr<EVP_PKEY> key, bool includePrivate = true);
    static Bytes toRaw25519(std::shared_ptr<EVP_PKEY> key, bool includePrivate = true);
    static Bytes toRawPQ(std::shared_ptr<EVP_PKEY> key, bool includePrivate = true);

    static std::shared_ptr<EVP_PKEY> fromRaw(AsymAlg, BytesView data, bool includePrivate = true);
    static std::shared_ptr<EVP_PKEY> fromRawP256(const char *groupname, BytesView data, bool includePrivate = true);
    static std::shared_ptr<EVP_PKEY> fromRaw25519(const char *name, BytesView data, bool includePrivate = true);
    static std::shared_ptr<EVP_PKEY> fromRawPQ(const char *name, BytesView data, size_t publen, size_t privlen = 0, size_t seedlen = 0);

    static std::shared_ptr<EVP_PKEY> fromRawP256PrivateOnly(const char *groupname, BytesView rawdata);

    // not work as expected - for tests only - TO REMOVE (or replace)
    static std::shared_ptr<EVP_PKEY> fromRawPrivateP256(const char *groupname, BytesView data);
    
    // based on example from https://github.com/openssl/openssl/issues/18437
    static Bytes GetPubKeyFromPrivKey(EVP_PKEY* ec_key, bool toCompress = false, bool toSet = false);

    static Bytes sign(AsymAlg alg, SigScheme scheme, EVP_PKEY *raw_pkey, BytesView message);
    static Bytes sign(AsymAlg, EVP_PKEY *raw_pkey, BytesView message);

    static bool verify(AsymAlg algorithm, SigScheme scheme, EVP_PKEY *raw_pkey, BytesView message, BytesView signature);
    static bool verify(AsymAlg, EVP_PKEY *raw_pkey, BytesView message, BytesView signature);

    static Bytes compressPublic(Bytes rawdata);

    static Bytes signAsn2rs(BytesView signatureANS1);
    static Bytes signRS2Asn(BytesView signatureRS);

    static Bytes sign64to65(BytesView sign64);
    static Bytes sign65to64(BytesView sign65);

    
// protected:
private:
    static Bytes sign_ds(EVP_PKEY *raw_pkey, BytesView message, 
        const EVP_MD *digest_type = NULL, ENGINE *e = NULL);
    static Bytes sign_ds_ex(EVP_PKEY *raw_pkey, BytesView message, 
        const char *mdname = NULL, const OSSL_PARAM *params = NULL);
    // Following method requires a higher version of OpenSSL library:    
    // static Bytes sign_ms(EVP_PKEY *raw_pkey, BytesView message, 
    //     const char *algorithm, const OSSL_PARAM *params = NULL);

    static bool verify_ds(EVP_PKEY *raw_pkey, BytesView message, BytesView signature, 
        const EVP_MD *digest_type = NULL, ENGINE *e = NULL);
    static bool verify_ds_ex(EVP_PKEY *raw_pkey, BytesView message, BytesView signature, 
        const char *mdname = NULL, const OSSL_PARAM *params = NULL);
    // Following method requires a higher version of OpenSSL library:    
    // static Bytes verify_ms(EVP_PKEY *raw_pkey, BytesView message, BytesView signature, 
    //     const char *algorithm, const OSSL_PARAM *params = NULL);

    static Bytes derive(EVP_PKEY *hostkey, EVP_PKEY* peerkey);
    static std::pair<Bytes, Bytes> encapsulate(EVP_PKEY* peerkey);

    static Bytes decapsulate(EVP_PKEY* hostkey, BytesView ciphertext);
};

// } // ecc
} // cryptoservice
} // privmx

#endif // _PRIVMXLIB_CRYPTOSERVICE_ASYNCKEYUTILS_HPP_