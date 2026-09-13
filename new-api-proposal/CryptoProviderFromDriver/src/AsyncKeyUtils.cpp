/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <functional>
#include <memory>
#include <string>
#include <typeinfo>
#include <map>

#include <iostream> // for showParams() only

#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/ec.h>

#include <openssl/core_names.h>
#include <openssl/core.h>

#include <openssl/engine.h>

#include "CoreTypes.hpp"
// #include "CoreInterfaces.hpp"

#include "AsyncKeyUtils.hpp"

#include "Exceptions.hpp"

namespace privmx {
namespace cryptoservice {
// namespace ecc {


void AsyncKeyUtils::showParams(std::shared_ptr<EVP_PKEY> key) {
    EVP_PKEY *pkey = key.get();

     if (pkey == NULL) {
           std::cout << "   struktura klucza nie zainicjalizowana!\n";
           return;
        }
 
        std::cout << "id typu klucza = " << EVP_PKEY_get_id(pkey) << "\n";
        std::cout << "lista parametrow klucza, ich typów i rozmiarów:\n";
        OSSL_PARAM *param_array;
        if (EVP_PKEY_todata(pkey, EVP_PKEY_KEYPAIR, &param_array) == 0)
            throw std::runtime_error("cannot read parameters");
        for (OSSL_PARAM *p = param_array; p->key; p++) {
//            std::cout << std::string(p->key) << " type = " << p->data_type << std::endl;
        const char *datatype = NULL;

        switch (p->data_type) {
        case OSSL_PARAM_INTEGER:
            datatype = "integer";
            break;
        case OSSL_PARAM_UNSIGNED_INTEGER:
            datatype = "unsigned integer";
            break;
        case OSSL_PARAM_UTF8_STRING:
            datatype = "printable string (utf-8 encoding expected)";
            break;
        case OSSL_PARAM_UTF8_PTR:
            datatype = "printable string pointer (utf-8 encoding expected)";
            break;
        case OSSL_PARAM_OCTET_STRING:
            datatype = "octet string";
            break;
        case OSSL_PARAM_OCTET_PTR:
            datatype = "octet string pointer";
            break;
        }
            std::cout << " * " << std::string(p->key) << " [type = ";
            std::cout << datatype << " (size: " << p-> data_size << ")]\n";
        if (p->data_type == OSSL_PARAM_UTF8_STRING) {
            char buffer[200], *buffer_ptr = buffer;
            if (OSSL_PARAM_get_utf8_string(p, &buffer_ptr, sizeof buffer) != 1) {
                std::cout << "     [ failed to read parameter ]\n";
            } else {
                std::cout << "    \"" << buffer << "\"\n";
            }
        }

        }
        std::cout << "(koniec parametrów)\n\n"; 
    OSSL_PARAM_free(param_array);
}

std::shared_ptr<EVP_PKEY> AsyncKeyUtils::fromRaw(AsymAlg algorithm, BytesView rawdata, bool includePrivate) {
    switch (algorithm)
    {
    case AsymAlg::secp256k1:
        return fromRawP256(rawdata, "secp256k1", includePrivate);
    case AsymAlg::prime256v1:
//        return fromRawP256(rawdata, "P-256", includePrivate);
        return fromRawP256(rawdata, "prime256v1", includePrivate);
    case AsymAlg::brainpoolP256r1:
        return fromRawP256(rawdata, "brainpoolP256r1", includePrivate);
    case AsymAlg::X25519:
        return fromRaw25519("X25519", rawdata, includePrivate);
    case AsymAlg::ED25519:
        return fromRaw25519("ED25519", rawdata, includePrivate);
    case AsymAlg::MLKEM768:
        return fromRawPQ("ML-KEM-768", rawdata, 1184, includePrivate ? 2400 : 0, includePrivate ? 64 : 0);
    case AsymAlg::MLDSA65:
        return fromRawPQ("ML-DSA-65", rawdata, 1952, includePrivate ? 4032 : 0, includePrivate ? 32 : 0);
    default:
        throw PrivmxCryptoserviceAsyncKeyException("Key import function: Unknown protocol");
        break;
    }
    throw PrivmxCryptoserviceAsyncKeyException("Key import function: Unknown protocol");
}

/// @brief Create private key from from private and public keys data
/// @param rawdata Raw 65 bytes of public key data optionally followed by 32 bytes of private key data  
/// @param groupname Name of the curve group ("secp256k1", "prime256v1" or "brainpoolP256r1")
/// @param includePrivate Include public part if true and if rawdata contain private part 
/// @return Shared pointer to the EVP_PKEY structure with desired key
std::shared_ptr<EVP_PKEY> AsyncKeyUtils::fromRawP256(BytesView rawdata, const char *groupname, bool includePrivate)  {

    if (rawdata.size() != 32+65 && rawdata.size() != 65) {
        throw PrivmxCryptoserviceAsyncKeyException("Incorrect input data size");
    }

    ossl_param_bld_unique_ptr param_bld(OSSL_PARAM_BLD_new(),OSSL_PARAM_BLD_free);
    OSSL_PARAM_BLD *param_bld_raw = param_bld.get();
    if (param_bld_raw == NULL) {
        throw PrivmxCryptoserviceAsyncKeyException("Initialization of OSSL_PARAM_BLD structure fail");
    }

    if (OSSL_PARAM_BLD_push_utf8_string(param_bld_raw, "group",
                                           groupname, 0) == 0) {
        throw PrivmxCryptoserviceAsyncKeyException("Setting curve group fail");
    }

    bool isPrivate = false;
    bignum_unique_ptr priv;
    if (includePrivate && rawdata.size() == 32+65) {
        isPrivate = true;
        const unsigned char *priv_data = reinterpret_cast<const unsigned char*>(rawdata.data()+65);

        priv = bignum_unique_ptr(BN_bin2bn(priv_data, 32, NULL), BN_free);
        if (priv.get() == NULL) {
            throw PrivmxCryptoserviceAsyncKeyException("Raw private key data read failure");
        }

        if (OSSL_PARAM_BLD_push_BN(param_bld_raw, "priv", priv.get()) == 0) {
            throw PrivmxCryptoserviceAsyncKeyException("Setting key private part fail");
        }
    }

    const unsigned char *pub_data = reinterpret_cast<const unsigned char*>(rawdata.data());
    if (OSSL_PARAM_BLD_push_octet_string(param_bld_raw, "pub",
                                            pub_data, 65) == 0) {
        throw PrivmxCryptoserviceAsyncKeyException("Setting key public part fail");
    }

    ossl_param_unique_ptr params(OSSL_PARAM_BLD_to_param(param_bld_raw),OSSL_PARAM_free);
    if (params.get() == NULL) {
        throw PrivmxCryptoserviceAsyncKeyException("Initialization of OSSL_PARAM structure fail");
    }

    evp_pkey_ctx_unique_ptr ctx(EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL), EVP_PKEY_CTX_free);
    EVP_PKEY_CTX *ctx_raw = ctx.get();
    if (ctx_raw == NULL) {
        throw PrivmxCryptoserviceAsyncKeyException("Create of key context structure fail");
    }

    if (EVP_PKEY_fromdata_init(ctx_raw) <= 0) {
        throw PrivmxCryptoserviceAsyncKeyException("Initialization of key context structure fail");
    }

    EVP_PKEY *pkey = NULL;
// // EVP_PKEY_KEYPAIR should be acceptable in all cases (if "priv" part is not set it the generated key is public one)
//    if (EVP_PKEY_fromdata(ctx_raw, &pkey, EVP_PKEY_KEYPAIR, params.get()) <= 0) {
    if (EVP_PKEY_fromdata(ctx_raw, &pkey, isPrivate ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY, params.get()) <= 0) {
        throw PrivmxCryptoserviceAsyncKeyException("Initialization of EVP_PKEY structure fail");
    }

    evp_pkey_unique_ptr result (pkey, EVP_PKEY_free);
    return std::move(result);
}


/// @brief Create private key from from private and public keys data
/// @param rawdata Raw 32 bytes of private key data  
/// @param groupname Name of the curve group ("secp256k1", "prime256v1" or "brainpoolP256r1")
/// @return Shared pointer to the EVP_PKEY structure with desired key
std::shared_ptr<EVP_PKEY> AsyncKeyUtils::fromRawP256PrivateOnly(BytesView rawdata, const char *groupname)  {
    if (rawdata.size() != 32) {
        throw PrivmxCryptoserviceAsyncKeyException("Incorrect input data size");
    }

    ossl_param_bld_unique_ptr param_bld(OSSL_PARAM_BLD_new(),OSSL_PARAM_BLD_free);
    OSSL_PARAM_BLD *param_bld_raw = param_bld.get();
    if (param_bld_raw == NULL) {
        throw PrivmxCryptoserviceAsyncKeyException("Initialization of OSSL_PARAM_BLD structure fail");
    }

    if (OSSL_PARAM_BLD_push_utf8_string(param_bld_raw, "group",
                                           groupname, 0) == 0) {
        throw PrivmxCryptoserviceAsyncKeyException("Setting curve group fail");
    }

    const unsigned char *priv_data = reinterpret_cast<const unsigned char*>(rawdata.data());
    bignum_unique_ptr priv = bignum_unique_ptr(BN_bin2bn(priv_data, 32, NULL), BN_free);
    if (priv.get() == NULL) {
        throw PrivmxCryptoserviceAsyncKeyException("Raw private key data read failure");
    }

    if (OSSL_PARAM_BLD_push_BN(param_bld_raw, "priv", priv.get()) == 0) {
        throw PrivmxCryptoserviceAsyncKeyException("Setting key private part fail");
    }

    ossl_param_unique_ptr params(OSSL_PARAM_BLD_to_param(param_bld_raw),OSSL_PARAM_free);
    if (params.get() == NULL) {
        throw PrivmxCryptoserviceAsyncKeyException("Initialization of OSSL_PARAM structure fail");
    }

    evp_pkey_ctx_unique_ptr ctx(EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL), EVP_PKEY_CTX_free);
    EVP_PKEY_CTX *ctx_raw = ctx.get();
    if (ctx_raw == NULL) {
        throw PrivmxCryptoserviceAsyncKeyException("Create of key context structure fail");
    }

    if (EVP_PKEY_fromdata_init(ctx_raw) <= 0) {
        throw PrivmxCryptoserviceAsyncKeyException("Initialization of key context structure fail");
    }

    EVP_PKEY *pkey = NULL;
// // EVP_PKEY_KEYPAIR should be acceptable in all cases
//    if (EVP_PKEY_fromdata(ctx_raw, &pkey, EVP_PKEY_KEYPAIR, params.get()) <= 0) {
    if (EVP_PKEY_fromdata(ctx_raw, &pkey, EVP_PKEY_PRIVATE_KEY, params.get()) <= 0) {
        throw PrivmxCryptoserviceAsyncKeyException("Initialization of EVP_PKEY structure fail");
    }

    evp_pkey_unique_ptr result (pkey, EVP_PKEY_free);
    return std::move(result);
}

/// NOT WORK AS DESIRED
/// @brief Create private key from from private key data
/// @param rawdata Raw 32 bytes of private key data  
/// @param groupname Name of the curve group ("secp256k1", "prime256v1" or "brainpoolP256r1")
/// @return Shared pointer to the EVP_PKEY structure with desired key
std::shared_ptr<EVP_PKEY> AsyncKeyUtils::fromRawPrivateP256(const char *groupname, BytesView rawdata)  {

    if (rawdata.size() != 32) {
        throw PrivmxCryptoserviceAsyncKeyException("Incorrect input data size");
    }

    ossl_param_bld_unique_ptr param_bld(OSSL_PARAM_BLD_new(),OSSL_PARAM_BLD_free);
    OSSL_PARAM_BLD *param_bld_raw = param_bld.get();
    if (param_bld_raw == NULL) {
        throw PrivmxCryptoserviceAsyncKeyException("Initialization of OSSL_PARAM_BLD structure fail");
    }

    if (OSSL_PARAM_BLD_push_utf8_string(param_bld_raw, "group",
                                           groupname, 0) == 0) {
        throw PrivmxCryptoserviceAsyncKeyException("Setting curve group fail");
    }

    const unsigned char *priv_data = reinterpret_cast<const unsigned char*>(rawdata.data());
    bignum_unique_ptr priv = bignum_unique_ptr(BN_bin2bn(priv_data, 32, NULL), BN_free);;
    if (priv.get() == NULL) {
        throw PrivmxCryptoserviceAsyncKeyException("Raw private key data read failure");
    }
    if (OSSL_PARAM_BLD_push_BN(param_bld_raw, "priv", priv.get()) == 0) {
        throw PrivmxCryptoserviceAsyncKeyException("Setting key private part fail");
    }

    // const unsigned char *pub_data = reinterpret_cast<const unsigned char*>(rawdata.data());
    // if (OSSL_PARAM_BLD_push_octet_string(param_bld_raw, "pub",
    //                                         pub_data, 65) == 0) {
    //     throw PrivmxCryptoserviceAsyncKeyException("Setting key public part fail");
    // }

    ossl_param_unique_ptr params(OSSL_PARAM_BLD_to_param(param_bld_raw),OSSL_PARAM_free);
    OSSL_PARAM *params_raw = params.get();
    if (params_raw == NULL) {
        throw PrivmxCryptoserviceAsyncKeyException("Initialization of OSSL_PARAM structure fail");
    }

    evp_pkey_ctx_unique_ptr ctx(EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL), EVP_PKEY_CTX_free);
    EVP_PKEY_CTX *ctx_raw = ctx.get();
    if (ctx_raw == NULL) {
        throw PrivmxCryptoserviceAsyncKeyException("Create of key context structure fail");
    }

    if (EVP_PKEY_keygen_init(ctx_raw) <= 0) {
        throw PrivmxCryptoserviceAsyncKeyException("Failed to initialize keygen");
    }

    if (EVP_PKEY_CTX_set_params(ctx_raw, params_raw) <= 0) {
        throw PrivmxCryptoserviceAsyncKeyException("Failed to set private key parameters on context");
    }

    // Override private part with new one
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx_raw, &pkey) <= 0) {
        throw PrivmxCryptoserviceAsyncKeyException("Key generation failed");
    }

    evp_pkey_unique_ptr result (pkey, EVP_PKEY_free);
    return std::move(result);
}

/// @brief Create private key from from private and public keys data
/// @param name Name of the key algorithm (X25519 or ED25519)
/// @param rawdata Raw 32 bytes of public key data optionally followed by 32 bytes of private key data  
/// @param includePrivate Include public part if true and if rawdata contain private part 
/// @return Shared pointer to the EVP_PKEY structure with desired key
std::shared_ptr<EVP_PKEY> AsyncKeyUtils::fromRaw25519(const char *name, BytesView rawdata, bool includePrivate) {

    if (rawdata.size() != 32+32 && rawdata.size() != 32) {
        throw PrivmxCryptoserviceAsyncKeyException("Incorrect input data size");
    }

    ossl_param_bld_unique_ptr param_bld(OSSL_PARAM_BLD_new(),OSSL_PARAM_BLD_free);
    OSSL_PARAM_BLD *param_bld_raw = param_bld.get();
    if (param_bld_raw == NULL) {
        throw PrivmxCryptoserviceAsyncKeyException("Initialization of OSSL_PARAM_BLD structure fail");
    }

    if (includePrivate && rawdata.size() == 32+32) {
        const unsigned char *priv_data = reinterpret_cast<const unsigned char*>(rawdata.data()+32);
        if (OSSL_PARAM_BLD_push_octet_string(param_bld_raw, "priv",
                                            priv_data, 32) == 0) {
            throw PrivmxCryptoserviceAsyncKeyException("Setting key private part fail");
        }
    }

    const unsigned char *pub_data = reinterpret_cast<const unsigned char*>(rawdata.data());
    if (OSSL_PARAM_BLD_push_octet_string(param_bld_raw, "pub",
                                            pub_data, 32) == 0) {
        throw PrivmxCryptoserviceAsyncKeyException("Setting key public part fail");
    }

    ossl_param_unique_ptr params(OSSL_PARAM_BLD_to_param(param_bld_raw),OSSL_PARAM_free);
    if (params.get() == NULL) {
        throw PrivmxCryptoserviceAsyncKeyException("Initialization of OSSL_PARAM structure fail");
    }

    evp_pkey_ctx_unique_ptr ctx(EVP_PKEY_CTX_new_from_name(NULL, name, NULL), EVP_PKEY_CTX_free);
    EVP_PKEY_CTX *ctx_raw = ctx.get();
    if (ctx_raw == NULL) {
        throw PrivmxCryptoserviceAsyncKeyException("Create of key context structure fail");
    }

    if (EVP_PKEY_fromdata_init(ctx_raw) <= 0) {
        throw PrivmxCryptoserviceAsyncKeyException("Initialization of key context structure fail");
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_fromdata(ctx_raw, &pkey, EVP_PKEY_KEYPAIR, params.get()) <= 0) {
        throw PrivmxCryptoserviceAsyncKeyException("Initialization of EVP_PKEY structure fail");
    }

    evp_pkey_unique_ptr result (pkey, EVP_PKEY_free);
    return std::move(result);
}

std::shared_ptr<EVP_PKEY> AsyncKeyUtils::fromRawPQ(const char *name, BytesView rawdata, size_t publen, size_t privlen, size_t seedlen) {

    if (rawdata.size() != publen + privlen + seedlen && rawdata.size() != publen) {
        throw PrivmxCryptoserviceAsyncKeyException("Incorrect input data size");
    }

    ossl_param_bld_unique_ptr param_bld(OSSL_PARAM_BLD_new(),OSSL_PARAM_BLD_free);
    OSSL_PARAM_BLD *param_bld_raw = param_bld.get();
    if (param_bld_raw == NULL) {
        throw PrivmxCryptoserviceAsyncKeyException("Initialization of OSSL_PARAM_BLD structure fail");
    }

    if (rawdata.size() != publen) {
        const unsigned char *seed_data = reinterpret_cast<const unsigned char*>(rawdata.data()+publen+privlen);
        if (OSSL_PARAM_BLD_push_octet_string(param_bld_raw, "seed",
                                            seed_data, seedlen) == 0) {
            throw PrivmxCryptoserviceAsyncKeyException("Setting key seed fail");
        }
        const unsigned char *priv_data = reinterpret_cast<const unsigned char*>(rawdata.data()+publen);
        if (OSSL_PARAM_BLD_push_octet_string(param_bld_raw, "priv",
                                            priv_data, privlen) == 0) {
            throw PrivmxCryptoserviceAsyncKeyException("Setting key private part fail");
        }
    }

    const unsigned char *pub_data = reinterpret_cast<const unsigned char*>(rawdata.data());
    if (OSSL_PARAM_BLD_push_octet_string(param_bld_raw, "pub",
                                            pub_data, publen) == 0) {
        throw PrivmxCryptoserviceAsyncKeyException("Setting key public part fail");
    }

    ossl_param_unique_ptr params(OSSL_PARAM_BLD_to_param(param_bld_raw),OSSL_PARAM_free);
    if (params.get() == NULL) {
        throw PrivmxCryptoserviceAsyncKeyException("Initialization of OSSL_PARAM structure fail");
    }

    evp_pkey_ctx_unique_ptr ctx(EVP_PKEY_CTX_new_from_name(NULL, name, NULL), EVP_PKEY_CTX_free);
    EVP_PKEY_CTX *ctx_raw = ctx.get();
    if (ctx_raw == NULL) {
        throw PrivmxCryptoserviceAsyncKeyException("Create of key context structure fail");
    }

    if (EVP_PKEY_fromdata_init(ctx_raw) <= 0) {
        throw PrivmxCryptoserviceAsyncKeyException("Initialization of key context structure fail");
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_fromdata(ctx_raw, &pkey, EVP_PKEY_KEYPAIR, params.get()) <= 0) {
        throw PrivmxCryptoserviceAsyncKeyException("Initialization of EVP_PKEY structure fail");
    }

    evp_pkey_unique_ptr result (pkey, EVP_PKEY_free);
    return std::move(result);
}

/// @brief Agnostic method to generate random keypair
/// @param algorithm Assymetric algorithm
/// @return Generated EVP_PKEY key containing both public and private parts
std::shared_ptr<EVP_PKEY> AsyncKeyUtils::getRandomKey(AsymAlg algorithm) {
    // if (algorithm == AsymAlg::SecP256r1) {
    //     evp_pkey_unique_ptr pkey(EVP_EC_gen("P-256"), EVP_PKEY_free);
    //     return std::move(pkey);
    // } else if(algorithm == AsymAlg::X25519) {  
    //   ...
    // }
    switch (algorithm)
    {
    case AsymAlg::secp256k1:
        return std::move(evp_pkey_unique_ptr(EVP_EC_gen("secp256k1"), EVP_PKEY_free));
    case AsymAlg::prime256v1:
        return std::move(evp_pkey_unique_ptr(EVP_EC_gen("P-256"), EVP_PKEY_free));
    case AsymAlg::brainpoolP256r1:
        return std::move(evp_pkey_unique_ptr(EVP_EC_gen("brainpoolP256r1"), EVP_PKEY_free));
    case AsymAlg::X25519:
        return std::move(evp_pkey_unique_ptr(EVP_PKEY_Q_keygen(NULL, NULL, "X25519"), EVP_PKEY_free));
    // or
    //     return getKeyFromId(EVP_PKEY_X25519);
    // or
    //     return getKeyFromName("X25519");
    case AsymAlg::ED25519:
        return std::move(evp_pkey_unique_ptr(EVP_PKEY_Q_keygen(NULL, NULL, "ED25519"), EVP_PKEY_free));
    //     return getKeyFromId(EVP_PKEY_ED25519);
    //     return getKeyFromName("ED25519");
    case AsymAlg::MLKEM768:
        return std::move(evp_pkey_unique_ptr(EVP_PKEY_Q_keygen(NULL, NULL, "ML-KEM-768"), EVP_PKEY_free));
    case AsymAlg::MLDSA65:
        return std::move(evp_pkey_unique_ptr(EVP_PKEY_Q_keygen(NULL, NULL, "ML-DSA-65"), EVP_PKEY_free));
    default:
        throw PrivmxCryptoserviceAsyncKeyException("Key genere function: Unknown protocol");
        break;
    }
    throw PrivmxCryptoserviceAsyncKeyException("Key generate function: Unknown protocol");
}

std::shared_ptr<EVP_PKEY> AsyncKeyUtils::getKeyFromId(int id) {
    evp_pkey_ctx_unique_ptr ctx(EVP_PKEY_CTX_new_id(id, NULL), EVP_PKEY_CTX_free);
    EVP_PKEY_CTX *ctx_raw = ctx.get();
    if (ctx_raw == NULL) {
        throw PrivmxCryptoserviceAsyncKeyException("Create of key context structure fail");
    }

    if (EVP_PKEY_keygen_init(ctx_raw) <= 0) {
        throw PrivmxCryptoserviceAsyncKeyException("Initialization of key context fail");
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx_raw, &pkey) <= 0){
        throw PrivmxCryptoserviceAsyncKeyException("Generate key fail");
    }

    return std::move(evp_pkey_unique_ptr(pkey, EVP_PKEY_free));
}

std::shared_ptr<EVP_PKEY> AsyncKeyUtils::getKeyFromName(const char *name) {
    evp_pkey_ctx_unique_ptr ctx(EVP_PKEY_CTX_new_from_name(NULL, name, NULL), EVP_PKEY_CTX_free);
    EVP_PKEY_CTX *ctx_raw = ctx.get();
    if (ctx_raw == NULL) {
        throw PrivmxCryptoserviceAsyncKeyException("Create of key context structure fail");
    }

    if (EVP_PKEY_keygen_init(ctx_raw) <= 0) {
        throw PrivmxCryptoserviceAsyncKeyException("Initialization of key context fail");
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx_raw, &pkey) <= 0){
        throw PrivmxCryptoserviceAsyncKeyException("Generate key fail");
    }

    return std::move(evp_pkey_unique_ptr(pkey, EVP_PKEY_free));
}

std::shared_ptr<EVP_PKEY> AsyncKeyUtils::getKeyFromNameAndSeed(const char *name, BytesView seed) {
// EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);
// EVP_PKEY_keygen_init(pctx);
// // seed_bytes is a 64-byte unsigned char array
// OSSL_PARAM params[2];
// params[0] = OSSL_PARAM_construct_octet_string("seed", seed_bytes, 64);
// params[1] = OSSL_PARAM_end();

// EVP_PKEY_CTX_set_params(pctx, params);
// EVP_PKEY *pkey = NULL;
// EVP_PKEY_keygen(pctx, &pkey);

    evp_pkey_ctx_unique_ptr ctx(EVP_PKEY_CTX_new_from_name(NULL, name, NULL), EVP_PKEY_CTX_free);
    EVP_PKEY_CTX *ctx_raw = ctx.get();
    if (ctx_raw == NULL) {
        throw PrivmxCryptoserviceAsyncKeyException("Create of key context structure fail");
    }

    if (EVP_PKEY_keygen_init(ctx_raw) <= 0) {
        throw PrivmxCryptoserviceAsyncKeyException("Initialization of key context fail");
    }

    // // we assume that seed is of correct size
    // OSSL_PARAM params[] = {
    //     OSSL_PARAM_construct_octet_string("seed", seed.data(), seed.size());
    //     OSSL_PARAM_END
    // };

    // we assume that seed is of correct size
    const OSSL_PARAM raw_params[] = {
        { "seed", OSSL_PARAM_OCTET_STRING, (void *) (seed.data()), seed.size(), 0 },
        { NULL, 0, NULL, 0, 0 }
    };

    if (EVP_PKEY_CTX_set_params(ctx_raw, raw_params) <= 0) {
        throw PrivmxCryptoserviceAsyncKeyException("Setting key seed fail");
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx_raw, &pkey) <= 0){
        throw PrivmxCryptoserviceAsyncKeyException("Generate key fail");
    }

    return std::move(evp_pkey_unique_ptr(pkey, EVP_PKEY_free));
}



Bytes AsyncKeyUtils::toRaw(AsymAlg algorithm, std::shared_ptr<EVP_PKEY> key, bool includePrivate) {
    // The following construction will not work in general
    // because EVP_PKEY_get_id() will return -1 for MLKEM and MLDSA algorithms
    // 
    // switch (EVP_PKEY_get_id(key.get()) 
    // {
    //     ...     
    // }
    
    switch (algorithm)
    {
    case AsymAlg::secp256k1:
    case AsymAlg::prime256v1:
    case AsymAlg::brainpoolP256r1:
    // case AsymAlg::prime256v1:
        return toRawP256(key, includePrivate);
    case AsymAlg::X25519:
    case AsymAlg::ED25519:
        return toRaw25519(key, includePrivate);
    case AsymAlg::MLKEM768:
    case AsymAlg::MLDSA65:
        return toRawPQ(key, includePrivate);
    default:
        throw PrivmxCryptoserviceAsyncKeyException("Key genere function: Unknown protocol");
        break;
    }
    throw PrivmxCryptoserviceAsyncKeyException("Key generate function: Unknown protocol");
}

Bytes AsyncKeyUtils::toRawP256(std::shared_ptr<EVP_PKEY> key, bool includePrivate) {
    EVP_PKEY *pkey = key.get();
    OSSL_PARAM *params_raw = NULL;
    if (EVP_PKEY_todata(pkey, EVP_PKEY_KEYPAIR, &params_raw) != 1) {
        throw PrivmxCryptoserviceAsyncKeyException("EVP_PKEY_todata failed");
    }
    ossl_param_unique_ptr params(params_raw,OSSL_PARAM_free);

    // Locate the specific parameter for the public key within the array
    OSSL_PARAM *ppub = OSSL_PARAM_locate(params.get(), OSSL_PKEY_PARAM_PUB_KEY);
    if (ppub == NULL) {
        throw PrivmxCryptoserviceAsyncKeyException("Public key parameter not found");
    }

    const size_t priv_key_len = 32;
    size_t pub_key_len = 65;
    size_t key_len = pub_key_len;
    if (includePrivate) key_len = priv_key_len + pub_key_len; 
    Bytes result(key_len);
    unsigned char *res_pub_d = reinterpret_cast<unsigned char*>(result.data());
    if (OSSL_PARAM_get_octet_string(ppub, (void **)&res_pub_d, pub_key_len, &pub_key_len) != 1) {
        PrivmxCryptoserviceAsyncKeyException("Failed to get public key raw bytes");
    }
    if(pub_key_len != 65) {
        PrivmxCryptoserviceAsyncKeyException("Invalid public key size");
    } 

    if (includePrivate) {
        // Locate the specific parameter for the private key within the array
        OSSL_PARAM *ppriv = OSSL_PARAM_locate(params.get(), OSSL_PKEY_PARAM_PRIV_KEY);
        if (ppriv == NULL) {
            throw PrivmxCryptoserviceAsyncKeyException("Private key parameter not found");
        }
        BIGNUM *priv_raw = NULL;
        if (OSSL_PARAM_get_BN(ppriv, &priv_raw) != 1) {
            throw PrivmxCryptoserviceAsyncKeyException("Failed to get private key raw bytes");
        }
        bignum_unique_ptr priv(priv_raw, BN_free);
        if (BN_num_bytes(priv_raw) > 32) {
           PrivmxCryptoserviceAsyncKeyException("Wrong private key size");
        } 
        unsigned char *res_priv_d = reinterpret_cast<unsigned char*>(result.data()+pub_key_len);
        if(priv_key_len != BN_bn2bin(priv.get(), res_priv_d)) {
            PrivmxCryptoserviceAsyncKeyException("Wrong private key size");
        } 
    }

    return result;
}

Bytes AsyncKeyUtils::toRaw25519(std::shared_ptr<EVP_PKEY> key, bool includePrivate) {
    EVP_PKEY *pkey = key.get();
    OSSL_PARAM *params_raw = NULL;
    if (EVP_PKEY_todata(pkey, EVP_PKEY_KEYPAIR, &params_raw) != 1) {
        throw PrivmxCryptoserviceAsyncKeyException("EVP_PKEY_todata failed");
    }
    ossl_param_unique_ptr params(params_raw,OSSL_PARAM_free);

    // Locate the specific parameter for the public key within the array
    OSSL_PARAM *ppub = OSSL_PARAM_locate(params.get(), OSSL_PKEY_PARAM_PUB_KEY);
    if (ppub == NULL) {
        throw PrivmxCryptoserviceAsyncKeyException("Public key parameter not found");
    }

    size_t priv_key_len = 32;
    size_t pub_key_len = 32;
    size_t key_len = pub_key_len;
    if (includePrivate) key_len = priv_key_len + pub_key_len; 
    Bytes result(key_len);
    unsigned char *res_pub_d = reinterpret_cast<unsigned char*>(result.data());
    if (OSSL_PARAM_get_octet_string(ppub, (void **)&res_pub_d, pub_key_len, &pub_key_len) != 1) {
        PrivmxCryptoserviceAsyncKeyException("Failed to get public key raw bytes");
    }
    if(pub_key_len != 32) {
        PrivmxCryptoserviceAsyncKeyException("Invalid public key size");
    } 

    if (includePrivate) {
        // Locate the specific parameter for the private key within the array
        OSSL_PARAM *ppriv = OSSL_PARAM_locate(params.get(), OSSL_PKEY_PARAM_PRIV_KEY);
        if (ppriv == NULL) {
            throw PrivmxCryptoserviceAsyncKeyException("Private key parameter not found");
        }
        unsigned char *res_priv_d = reinterpret_cast<unsigned char*>(result.data()+pub_key_len);
        if (OSSL_PARAM_get_octet_string(ppriv, (void **)&res_priv_d, priv_key_len, &priv_key_len) != 1) {
            PrivmxCryptoserviceAsyncKeyException("Failed to get private key raw bytes");
        }
        if(priv_key_len != 32) {
            PrivmxCryptoserviceAsyncKeyException("Invalid private key size");
        } 
    }

    return result;
}

Bytes AsyncKeyUtils::toRawPQ(std::shared_ptr<EVP_PKEY> key, bool includePrivate) {
    EVP_PKEY *pkey = key.get();
    OSSL_PARAM *params_raw = NULL;
    if (EVP_PKEY_todata(pkey, EVP_PKEY_KEYPAIR, &params_raw) != 1) {
        throw PrivmxCryptoserviceAsyncKeyException("EVP_PKEY_todata failed");
    }
    ossl_param_unique_ptr params(params_raw,OSSL_PARAM_free);

    // Locate the specific parameter for the public key within the array
    OSSL_PARAM *ppub = OSSL_PARAM_locate(params.get(), OSSL_PKEY_PARAM_PUB_KEY);
    if (ppub == NULL) {
        throw PrivmxCryptoserviceAsyncKeyException("Public key parameter not found");
    }

    size_t pub_key_len = ppub -> data_size;
    size_t priv_key_len = 0;
    size_t seed_len = 0;
    OSSL_PARAM *ppriv = NULL;
    OSSL_PARAM *pseed = NULL;
    if (includePrivate) {
        // Locate the specific parameter for the private key within the array
        ppriv = OSSL_PARAM_locate(params.get(), OSSL_PKEY_PARAM_PRIV_KEY);
        if (ppriv == NULL) {
            throw PrivmxCryptoserviceAsyncKeyException("Private key parameter not found");
        }
        priv_key_len = ppriv -> data_size;
        // Locate the specific parameter for the seed within the array
        // Note that OSSL_PKEY_PARAM_EC_SEED, OSSL_PKEY_PARAM_ML_DSA_SEED
        // and OSSL_PKEY_PARAM_ML_KEM_SEED are ALL equal "seed"
        pseed = OSSL_PARAM_locate(params.get(), "seed");
        if (pseed == NULL) {
            throw PrivmxCryptoserviceAsyncKeyException("Seed parameter not found");
        }
        seed_len = pseed -> data_size;        
    }
    size_t key_len = seed_len + priv_key_len + pub_key_len;
    Bytes result(key_len);

    size_t len = pub_key_len;
    unsigned char *res_pub_d = reinterpret_cast<unsigned char*>(result.data());
    if (OSSL_PARAM_get_octet_string(ppub, (void **)&res_pub_d, pub_key_len, &len) != 1) {
        PrivmxCryptoserviceAsyncKeyException("Failed to get public key raw bytes");
    }
    if (pub_key_len != len) {
        PrivmxCryptoserviceAsyncKeyException("Invalid public key size");
    } 

    if (includePrivate) {
        len = priv_key_len;
        unsigned char *res_priv_d = reinterpret_cast<unsigned char*>(result.data()+pub_key_len);
        if (OSSL_PARAM_get_octet_string(ppriv, (void **)&res_priv_d, priv_key_len, &len) != 1) {
            PrivmxCryptoserviceAsyncKeyException("Failed to get private key raw bytes");
        }
        if(priv_key_len != len) {
            PrivmxCryptoserviceAsyncKeyException("Invalid private key size");

        } 
        len = seed_len;
        unsigned char *res_seed_d = reinterpret_cast<unsigned char*>(result.data()+pub_key_len+priv_key_len);
        if (OSSL_PARAM_get_octet_string(ppriv, (void **)&res_seed_d, seed_len, &len) != 1) {
            PrivmxCryptoserviceAsyncKeyException("Failed to get seed raw bytes");
        }
        if(seed_len != len) {
            PrivmxCryptoserviceAsyncKeyException("Invalid seed size");
        } 
    }

    return result;
}

Bytes AsyncKeyUtils::sign(AsymAlg algorithm, EVP_PKEY *raw_pkey, BytesView message) {
    switch (algorithm)
    {
    case AsymAlg::prime256v1:
        return sign_ds(raw_pkey, message, EVP_sha256());
    case AsymAlg::X25519:
        throw PrivmxCryptoserviceAsyncKeyException("Signature function: Unsupported operation for X25519 key");
    case AsymAlg::ED25519:
        return sign_ds_ex(raw_pkey, message);
    case AsymAlg::MLKEM768:
        throw PrivmxCryptoserviceAsyncKeyException("Signature function: Unsupported operation for ML-KEM-768 key");
    // case AsymAlg::MLDSA65:
    //     return sign_ms(raw_pkey, message, "ML-DSA-65");
    default:
        throw PrivmxCryptoserviceAsyncKeyException("Signature function: Unknown protocol");
        break;
    }
    throw PrivmxCryptoserviceAsyncKeyException("Signature function: Unknown protocol");
}

/// @brief Agnostic method to sign a message which initialize signing operation with EVP_DigestSignInit() method
/// @param raw_pkey Pointer to the "raw" EVP_PKEY structure of private key
/// @param message Message to sign
/// @param mdname Message digest algorithm name (optional)
/// @param params Array of additional parameters (optional)
/// @return Signature of the message
Bytes AsyncKeyUtils::sign_ds_ex(EVP_PKEY *raw_pkey, BytesView message, 
        const char *mdname, const OSSL_PARAM *params) 
// void do_sign(EVP_PKEY *ed_key, unsigned char *msg, size_t msg_len)
{
    // EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    evp_md_ctx_unique_ptr mdctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    EVP_MD_CTX *ctx_raw = mdctx.get();
    if (ctx_raw == NULL) {
        throw PrivmxCryptoserviceAsyncKeyException("Create of message digest context fail");
    }

    // const OSSL_PARAM params[] = {
    //     OSSL_PARAM_utf8_string ("instance", "Ed25519ctx", 10),
    //     OSSL_PARAM_octet_string("context-string", (unsigned char *)"A protocol defined context string", 33),
    //     OSSL_PARAM_END
    // };

    /* The input "params" is not needed if default options are acceptable.
       Use NULL in place of "params" in that case. */
    ;
    /* Initialise the DigestSign operation - mdname has been selected as the message digest function */
    if(EVP_DigestSignInit_ex(ctx_raw, NULL, mdname, NULL, NULL, raw_pkey, params) != 1) {
        throw PrivmxCryptoserviceAsyncKeyException("Initialization of message digest context fail");
    }
    /* Calculate the required size for the signature by passing a NULL buffer. */
    size_t sig_len;
    // EVP_DigestSign(md_ctx, NULL, &sig_len, msg, msg_len);
    const unsigned char *d = reinterpret_cast<const unsigned char *> (message.data());
    if(EVP_DigestSign(ctx_raw, NULL, &sig_len, d, message.size()) != 1) {
        throw PrivmxCryptoserviceAsyncKeyException("Obtaining signature size fail");
    }
    
    /* Allocate memory for the signature based on size in signlen */
    // unsigned char *sig = NULL;
    // sig = OPENSSL_zalloc(sig_len);
    Bytes signature(sig_len);
    unsigned char *sig = reinterpret_cast<unsigned char *> (signature.data());

    // Both update and finalize 
    if(EVP_DigestSign(ctx_raw, sig, &sig_len, d, message.size()) != 1) {
        throw PrivmxCryptoserviceAsyncKeyException("Sign operation fail");
    }

        if (signature.size() != sig_len) {
        // throw PrivmxCryptoserviceAsyncKeyException("Signature size error: ");
        std::string msg("Signature size error: ");
        msg = msg + std::to_string(signature.size()) 
                  + " vs "
                  + std::to_string(sig_len);
        if (sig_len > 0 && sig_len < signature.size())
            signature.resize(sig_len);
        else
            throw PrivmxCryptoserviceAsyncKeyException(msg);
    }
    // OPENSSL_free(sig);
    // EVP_MD_CTX_free(md_ctx);
    return signature;
}

/// @brief Agnostic method to sign a message which initialize signing operation with EVP_DigestSignInit() method
/// @param raw_pkey Pointer to the "raw" EVP_PKEY structure of private key
/// @param message Message to sign
/// @param digest_type Optional pointer to the digest algorithm (for example obtained by invoking "EVP_sha256()")
/// @param e Optional pointer to the provider engine
/// @return Signature of the message
Bytes AsyncKeyUtils::sign_ds(EVP_PKEY *raw_pkey, BytesView message, 
    const EVP_MD *digest_type, ENGINE *e) {
// Bytes PrivateKey2::sign(BytesView data) const {
    /* Create the Message Digest Context */
    // evp_md_ctx_unique_ptr mdctx(EVP_MD_CTX_create(), EVP_MD_CTX_destroy);
    evp_md_ctx_unique_ptr mdctx(EVP_MD_CTX_create(), EVP_MD_CTX_free);
    EVP_MD_CTX *ctx_raw = mdctx.get();
    if (ctx_raw == NULL) {
        throw PrivmxCryptoserviceAsyncKeyException("Create of message digest context fail");
    }
 
    /* Initialise the DigestSign operation - SHA-256 has been selected as the message digest function */
    // if(EVP_DigestSignInit(ctx_raw, NULL, EVP_sha256(), NULL, raw_pkey) != 1) {
    if(EVP_DigestSignInit(ctx_raw, NULL, digest_type, NULL, raw_pkey) != 1) {
        throw PrivmxCryptoserviceAsyncKeyException("Initialization of message digest context fail");
    }
    
    /* Call update with the message */
    if(EVP_DigestSignUpdate(ctx_raw, message.data(), message.size()) != 1) {
        throw PrivmxCryptoserviceAsyncKeyException("Update of signing message fail");
    }
    
 /* Finalise the DigestSign operation */
 /* First call EVP_DigestSignFinal with a NULL sig parameter to obtain the length of the
  * signature. Length is returned in signlen */
    size_t signlen;
    if(1 != EVP_DigestSignFinal(ctx_raw, NULL, &signlen)) {
        throw PrivmxCryptoserviceAsyncKeyException("Obtaining signature size fail");
    }
    // Note: the real length of signature may be lower that signlen

    /* Allocate memory for the signature based on size in signlen */
    Bytes signature(signlen);
    unsigned char *sig = reinterpret_cast<unsigned char *> (signature.data());

    if(EVP_DigestSignFinal(ctx_raw, sig, &signlen) != 1) {
        throw PrivmxCryptoserviceAsyncKeyException("Finalise the DigestSign operation fail");
    }

    if (signature.size() != signlen) {
        // throw PrivmxCryptoserviceAsyncKeyException("Signature size error: ");
        std::string msg("Signature size error: ");
        msg = msg + std::to_string(signature.size()) 
                  + " vs "
                  + std::to_string(signlen);
        if (signlen > 0 && signlen < signature.size())
            signature.resize(signlen);
        else
            throw PrivmxCryptoserviceAsyncKeyException(msg);
    }

    return signature;
}

// /// @brief Agnostic method to sign a message which initialize signing operation with EVP_DigestSignInit() method
// /// @param raw_pkey Pointer to the "raw" EVP_PKEY structure of private key
// /// @param message Message to sign
// /// @param algorithm Name of the signing algorithm (i.e. "ML-DSA-65")
// /// @param params Array of additional parameters (optional)
// /// @return Signature of the message
// Bytes AsyncKeyUtils::sign_ms(EVP_PKEY *raw_pkey, BytesView message, 
//     const char *algorithm, const OSSL_PARAM *params) 
// // void do_sign(EVP_PKEY *key, const unsigned char *msg, size_t msg_len)
// {
//     // OSSL_PARAM params[2];
//     // EVP_PKEY_CTX *sctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
//     evp_pkey_ctx_unique_ptr ctx(EVP_PKEY_CTX_new_from_pkey(NULL, raw_pkey, NULL), EVP_PKEY_CTX_free);
//     EVP_PKEY_CTX *ctx_raw = ctx.get();
//     if (ctx_raw == NULL) {
//         throw PrivmxCryptoserviceAsyncKeyException("Extraction of key context structure fail");
//     }

//     // EVP_SIGNATURE *sig_alg = EVP_SIGNATURE_fetch(NULL, "ML-DSA-65", NULL);
//     evp_signature_unique_ptr sig_alg(EVP_SIGNATURE_fetch(NULL, algorithm, NULL), EVP_SIGNATURE_free);
//     EVP_SIGNATURE *sig_alg_raw = sig_alg.get();
//     if (ctx_raw == NULL) {
//         throw PrivmxCryptoserviceAsyncKeyException("Extraction of key context structure fail");
//     }

//     // /* The context string is an optional parameter */
//     // params[0] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, (unsigned char *)"A context string", 16),
//     // params[1] = OSSL_PARAM_construct_end();

//     /* Initialise the sign operation */
//     // NOTE: EVP_PKEY_sign_message_init() is available from OpenSSL 3.4
//     // EVP_PKEY_sign_message_init(ctx_raw, sig_alg, params);
//     if(EVP_PKEY_sign_message_init(ctx_raw, sig_alg, params) != 1) {
//         throw PrivmxCryptoserviceAsyncKeyException("Initialization of message digest context fail");
//     }

//     /* Calculate the required size for the signature by passing a NULL buffer. */
//     size_t sig_len;
//     // EVP_DigestSign(md_ctx, NULL, &sig_len, msg, msg_len);
//     const unsigned char *d = reinterpret_cast<const unsigned char *> (message.data());
//     if(EVP_PKEY_sign(ctx_raw, NULL, &sig_len, d, message.size())) {
//         throw PrivmxCryptoserviceAsyncKeyException("Obtaining signature size fail");
//     }

//     /* Allocate memory for the signature based on size in signlen */
//     // unsigned char *sig = NULL;
//     // sig = OPENSSL_zalloc(sig_len);
//     Bytes signature(sig_len);
//     unsigned char *sig = reinterpret_cast<unsigned char *> (signature.data());

//     // Both update and finalize 
//     if(EVP_PKEY_sign(ctx_raw, sig, &sig_len, d, message.size()) != 1) {
//         throw PrivmxCryptoserviceAsyncKeyException("Sign operation fail");
//     }

//     if (signature.size() != sig_len) {
//         // throw PrivmxCryptoserviceAsyncKeyException("Signature size error: ");
//         std::string msg("Signature size error: ");
//         msg = msg + std::to_string(signature.size()) 
//                   + " vs "
//                   + std::to_string(sig_len);
//         if (sig_len > 0 && sig_len < signature.size())
//             signature.resize(sig_len);
//         else
//             throw PrivmxCryptoserviceAsyncKeyException(msg);
//     }
//     // OPENSSL_free(sig);
//     // EVP_SIGNATURE_free(sig_alg);
//     // EVP_PKEY_CTX_free(sctx);
//     return signature;
// }



bool AsyncKeyUtils::verify(AsymAlg algorithm, EVP_PKEY *raw_pkey, BytesView message, BytesView signature) {
    switch (algorithm)
    {
    case AsymAlg::secp256k1:
    case AsymAlg::prime256v1:
    case AsymAlg::brainpoolP256r1:
    // case AsymAlg::prime256v1:
        return verify_ds(raw_pkey, message, signature, EVP_sha256());
    case AsymAlg::X25519:
        throw PrivmxCryptoserviceAsyncKeyException("Signature function: Unsupported operation for X25519 key");
    case AsymAlg::ED25519:
        return verify_ds_ex(raw_pkey, message, signature);
    case AsymAlg::MLKEM768:
        throw PrivmxCryptoserviceAsyncKeyException("Signature function: Unsupported operation for ML-KEM-768 key");
    // case AsymAlg::MLDSA65:
    //     return verify_ms(raw_pkey, message, signature, "ML-DSA-65");
    default:
        throw PrivmxCryptoserviceAsyncKeyException("Signature function: Unknown protocol");
        break;
    }
    throw PrivmxCryptoserviceAsyncKeyException("Signature function: Unknown protocol");
}

bool AsyncKeyUtils::verify_ds(EVP_PKEY *raw_pkey, BytesView message, BytesView signature, 
    const EVP_MD *digest_type, ENGINE *e) {
// Bytes PrivateKey2::sign(BytesView data) const {
    /* Create the Message Digest Context */
    // evp_md_ctx_unique_ptr mdctx(EVP_MD_CTX_create(), EVP_MD_CTX_destroy);
    evp_md_ctx_unique_ptr mdctx(EVP_MD_CTX_create(), EVP_MD_CTX_free);
    EVP_MD_CTX *ctx_raw = mdctx.get();
    if (ctx_raw == NULL) {
        throw PrivmxCryptoserviceAsyncKeyException("Create of message digest context fail");
    }
 
    /* Initialise the DigestVerify operation - SHA-256 has been selected as the message digest function */
    // if(EVP_DigestVerifyInit(ctx_raw, NULL, EVP_sha256(), NULL, raw_pkey) != 1) {
    if(EVP_DigestVerifyInit(ctx_raw, NULL, digest_type, NULL, raw_pkey) != 1) {
        throw PrivmxCryptoserviceAsyncKeyException("Initialization of message digest context fail");
    }
    
    /* Call update with the message */
    if(EVP_DigestVerifyUpdate(ctx_raw, message.data(), message.size()) != 1) {
        throw PrivmxCryptoserviceAsyncKeyException("Update of message signature verification fail");
    }
    
    /* Finalise the DigestVerify operation */
    const unsigned char *sig = reinterpret_cast<const unsigned char *> (signature.data());    
    int result = EVP_DigestVerifyFinal(ctx_raw, sig, signature.size());
    // if (result < 0) { // For example: invalid signature format
    //     throw PrivmxCryptoserviceAsyncKeyException("Signature verification fail");
    // }
    return result == 1;
}

bool AsyncKeyUtils::verify_ds_ex(EVP_PKEY *raw_pkey, BytesView message, BytesView signature, 
        const char *mdname, const OSSL_PARAM *params) 
{
    evp_md_ctx_unique_ptr mdctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    EVP_MD_CTX *ctx_raw = mdctx.get();
    if (ctx_raw == NULL) {
        throw PrivmxCryptoserviceAsyncKeyException("Create of message digest context fail");
    }

    /* Initialise the DigestSign operation - mdname has been selected as the message digest function */
    if(EVP_DigestVerifyInit_ex(ctx_raw, NULL, mdname, NULL, NULL, raw_pkey, params) != 1) {
        throw PrivmxCryptoserviceAsyncKeyException("Initialization of message digest context fail");
    }

    // Both update and finalize 
    const unsigned char *d = reinterpret_cast<const unsigned char *> (message.data());
    const unsigned char *sig = reinterpret_cast<const unsigned char *> (signature.data());
    int result = EVP_DigestVerify(ctx_raw, sig, signature.size(), d, message.size());
    // if (result < 0) { // For example: invalid signature format
    //     throw PrivmxCryptoserviceAsyncKeyException("Signature verification fail");
    // }
    return result == 1;
}


Bytes AsyncKeyUtils::derive(EVP_PKEY *hostkey, EVP_PKEY* peerkey) {
    // ENGINE *eng = ...;
    // ctx = EVP_PKEY_CTX_new(pkey, engine);
    evp_pkey_ctx_unique_ptr ctx(EVP_PKEY_CTX_new(hostkey, NULL), EVP_PKEY_CTX_free);
    // evp_pkey_ctx_unique_ptr ctx(EVP_PKEY_CTX_new_from_pkey(NULL, hostkey, NULL), EVP_PKEY_CTX_free);
    EVP_PKEY_CTX *ctx_raw = ctx.get();
    if (ctx_raw == NULL) {
        PrivmxCryptoserviceAsyncKeyException("Failed to create key context");
    }

    if (EVP_PKEY_derive_init(ctx_raw) <= 0) {
        throw PrivmxCryptoserviceAsyncKeyException("Initialization of key context structure fail");
    }
    
    if (EVP_PKEY_derive_set_peer(ctx_raw, peerkey) <= 0) {
        throw PrivmxCryptoserviceAsyncKeyException("Setting peer key fail");
    }

    size_t skeylen;
    /* Determine buffer length */
    if (EVP_PKEY_derive(ctx_raw, NULL, &skeylen) <= 0) {
        throw PrivmxCryptoserviceAsyncKeyException("Determining secret share key size fail");
    }

    Bytes skey(skeylen);
    unsigned char *sk = reinterpret_cast<unsigned char *>(skey.data());

    if (EVP_PKEY_derive(ctx_raw, sk, &skeylen) <= 0) {
        throw PrivmxCryptoserviceAsyncKeyException("Derivation secret share key size fail");
    }

    return skey;
}

/// @brief 
/// @param peerkey public peer key
/// @return 
std::pair<Bytes, Bytes> AsyncKeyUtils::encapsulate(EVP_PKEY* peerkey) {
    // evp_pkey_ctx_unique_ptr ctx(EVP_PKEY_CTX_new(peerkey, NULL), EVP_PKEY_CTX_free);
    evp_pkey_ctx_unique_ptr ctx(EVP_PKEY_CTX_new_from_pkey(NULL, peerkey, NULL), EVP_PKEY_CTX_free);
    EVP_PKEY_CTX *ctx_raw = ctx.get();
    if (ctx_raw == NULL) {
        PrivmxCryptoserviceAsyncKeyException("Failed to create context from peer key");
    }

    if (EVP_PKEY_encapsulate_init(ctx_raw, NULL) <= 0) {
        throw PrivmxCryptoserviceAsyncKeyException("Initialization of encapsulaton context fail");
    }

    // // Note: EVP_PKEY_CTX_set_kem_op for algorithm ML-KEM ignores KEM options
    // //       for algorithms X25519 and EC acceptable option is "DHKEM"
    // if (EVP_PKEY_CTX_set_kem_op(ctx, "DHKEM") <= 0) {
    //     throw PrivmxCryptoserviceAsyncKeyException("Setting KEM option fail");
    // }
    
    size_t secretlen = 0, cipherlen = 0;
    /* Determine buffer length */   
    if (EVP_PKEY_encapsulate(ctx_raw, NULL, &cipherlen, NULL, &secretlen) <= 0) {
        throw PrivmxCryptoserviceAsyncKeyException("Determining shared secret and ciphertext size fail");
    }
    Bytes ciphertext(cipherlen);
    Bytes sharedsecret(secretlen);

    unsigned char *ss = reinterpret_cast<unsigned char *>(sharedsecret.data());
    unsigned char *ct = reinterpret_cast<unsigned char *>(ciphertext.data());

    if (EVP_PKEY_encapsulate(ctx_raw, ct, &cipherlen, ss, &secretlen) <= 0) {
        throw PrivmxCryptoserviceAsyncKeyException("Encapsulation fail");
    }

    if (ciphertext.size() != cipherlen || sharedsecret.size() != secretlen) {
        throw PrivmxCryptoserviceAsyncKeyException("Encapsulation shared secret or ciphertext size error");
    }

    return std::make_pair(sharedsecret, ciphertext);
}

/// @brief 
/// @param hostkey private local host key
/// @return 
Bytes AsyncKeyUtils::decapsulate(EVP_PKEY* hostkey, BytesView ciphertext) {
    // evp_pkey_ctx_unique_ptr ctx(EVP_PKEY_CTX_new(hostkey, NULL), EVP_PKEY_CTX_free);
    evp_pkey_ctx_unique_ptr ctx(EVP_PKEY_CTX_new_from_pkey(NULL, hostkey, NULL), EVP_PKEY_CTX_free);
    EVP_PKEY_CTX *ctx_raw = ctx.get();
    if (ctx_raw == NULL) {
        PrivmxCryptoserviceAsyncKeyException("Failed to create context from host key");
    }

    if (EVP_PKEY_decapsulate_init(ctx_raw, NULL) <= 0) {
        throw PrivmxCryptoserviceAsyncKeyException("Initialization of encapsulaton context fail");
    }

    // // Note: EVP_PKEY_CTX_set_kem_op for algorithm ML-KEM ignores KEM options
    // //       for algorithms X25519 and EC acceptable option is "DHKEM"
    // if (EVP_PKEY_CTX_set_kem_op(ctx, "DHKEM") <= 0) {
    //     throw PrivmxCryptoserviceAsyncKeyException("Setting KEM option fail");
    // }
    
    const unsigned char *ct = reinterpret_cast<const unsigned char *>(ciphertext.data());
    size_t secretlen = 0;
    /* Determine buffer length */   
    if (EVP_PKEY_decapsulate(ctx_raw, NULL, &secretlen, ct, ciphertext.size()) <= 0) {
        throw PrivmxCryptoserviceAsyncKeyException("Determining shared secret size fail");
    }
    Bytes sharedsecret(secretlen);

    unsigned char *ss = reinterpret_cast<unsigned char *>(sharedsecret.data());

    if (EVP_PKEY_decapsulate(ctx_raw, ss, &secretlen, ct, ciphertext.size()) <= 0) {
        throw PrivmxCryptoserviceAsyncKeyException("Decapsulation fail");
    }

    if (sharedsecret.size() != secretlen) {
        throw PrivmxCryptoserviceAsyncKeyException("Decapsulation shared secret size error");
    }

    return sharedsecret;
}

Bytes AsyncKeyUtils::GetPubKeyFromPrivKey(EVP_PKEY* ec_key)
{
	size_t pub_key_size = 0;
	EVP_PKEY_get_octet_string_param(ec_key, OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0, &pub_key_size);
	Bytes pub_key_buffer(pub_key_size);
	if (!EVP_PKEY_get_octet_string_param(ec_key, OSSL_PKEY_PARAM_PUB_KEY, pub_key_buffer.data(), pub_key_buffer.size(),
	                                     &pub_key_size))
	{
		size_t group_name_size = 0;
		EVP_PKEY_get_utf8_string_param(ec_key, OSSL_PKEY_PARAM_GROUP_NAME, nullptr, 0, &group_name_size);
		std::vector<char> group_name(group_name_size + 1);
		if (!EVP_PKEY_get_utf8_string_param(ec_key, OSSL_PKEY_PARAM_GROUP_NAME, group_name.data(), group_name.size(),
		                                    &group_name_size))
		{
			return {};
		}

		int group_nid = OBJ_sn2nid(group_name.data());
		if (group_nid == NID_undef)
		{
			return {};
		}

		auto* ec_group = EC_GROUP_new_by_curve_name(group_nid);
		if (ec_group == nullptr)
		{
			return {};
		}

		auto* pub_key = EC_POINT_new(ec_group);
		if (pub_key == nullptr)
		{
			EC_GROUP_free(ec_group);

			return {};
		}
		BIGNUM* priv_key = nullptr;
		if (!EVP_PKEY_get_bn_param(ec_key, OSSL_PKEY_PARAM_PRIV_KEY, &priv_key))
		{
			EC_POINT_free(pub_key);
			EC_GROUP_free(ec_group);

			return {};
		}

		if (!EC_POINT_mul(ec_group, pub_key, priv_key, nullptr, nullptr, nullptr))
		{
			EC_POINT_free(pub_key);
			EC_GROUP_free(ec_group);

			return {};
		}

		pub_key_size = EC_POINT_point2oct(ec_group, pub_key, POINT_CONVERSION_COMPRESSED, nullptr, 0, nullptr);
		if (pub_key_size == 0)
		{
			EC_POINT_free(pub_key);
			EC_GROUP_free(ec_group);

			return {};
		}
		pub_key_buffer.resize(pub_key_size);
		if (!EC_POINT_point2oct(ec_group, pub_key, POINT_CONVERSION_COMPRESSED, pub_key_buffer.data(),
		                        pub_key_buffer.size(), nullptr))
		{
			EC_POINT_free(pub_key);
			EC_GROUP_free(ec_group);

			return {};
		}

		EC_POINT_free(pub_key);
		EC_GROUP_free(ec_group);

		if (!EVP_PKEY_set_octet_string_param(ec_key, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, pub_key_buffer.data(),
		                                     pub_key_buffer.size()))
		{
			return {};
		}

		auto* pCtx = EVP_PKEY_CTX_new_from_pkey(nullptr, ec_key, nullptr);
		if (pCtx == nullptr)
		{
			return {};
		}

		if (!EVP_PKEY_public_check_quick(pCtx))
		{
			EVP_PKEY_CTX_free(pCtx);

			return {};
		}

		EVP_PKEY_CTX_free(pCtx);
	}

	return pub_key_buffer;
}

// } // ecc
} // cryptoservice
} // privmx
