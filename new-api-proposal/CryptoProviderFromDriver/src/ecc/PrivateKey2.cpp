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

// #include <openssl/bn.h>
// #include <Poco/SharedPtr.h>

#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/ec.h>

#include <openssl/core_names.h>
#include <openssl/core.h>

#include "CoreTypes.hpp"
// #include "CoreInterfaces.hpp"

#include "PublicKey2.hpp"
#include "PrivateKey2.hpp"
// #include "Base58.hpp"
// #include "Utils.hpp"

#include "EccExceptions.hpp"

namespace privmx {
namespace cryptoservice {
namespace ecc {

/// @brief Create private key from from private and public keys data
/// @param rawdata Raw 32 bytes of private key data followed by 65 bytes of public key data
/// @param p Optional provider for symmetric cryptography operations
PrivateKey2::PrivateKey2(BytesView rawdata, std::shared_ptr<ISymCryptoProvider> p) 
                        : _provider(p) {
    if (rawdata.size() != 32+65) {
        throw PrivmxCryptoserviceEccPrivateKeyException("Incorrect input data size");
    }
    const unsigned char *priv_data = reinterpret_cast<const unsigned char*>(rawdata.data());
    const unsigned char *pub_data = reinterpret_cast<const unsigned char*>(rawdata.data()+32);

    PrivateKey2::bignum_unique_ptr priv(BN_bin2bn(priv_data, 32, NULL), BN_free);
    if (priv.get() == NULL) {
        throw PrivmxCryptoserviceEccPrivateKeyException("Raw private key data read failure");
    }

    ossl_param_bld_unique_ptr param_bld(OSSL_PARAM_BLD_new(),OSSL_PARAM_BLD_free);
    OSSL_PARAM_BLD *param_bld_raw = param_bld.get();
    if (param_bld_raw == NULL) {
        throw PrivmxCryptoserviceEccPrivateKeyException("Initialization of OSSL_PARAM_BLD structure fail");
    }

    if (OSSL_PARAM_BLD_push_utf8_string(param_bld_raw, "group",
                                           "prime256v1", 0) == 0) {
        throw PrivmxCryptoserviceEccPrivateKeyException("Setting curve group fail");
    }

    if (OSSL_PARAM_BLD_push_BN(param_bld_raw, "priv", priv.get()) == 0) {
        throw PrivmxCryptoserviceEccPrivateKeyException("Setting key private part fail");
    }

    if (OSSL_PARAM_BLD_push_octet_string(param_bld_raw, "pub",
                                            pub_data, 65) == 0) {
        throw PrivmxCryptoserviceEccPrivateKeyException("Setting key public part fail");
    }

    ossl_param_unique_ptr params(OSSL_PARAM_BLD_to_param(param_bld_raw),OSSL_PARAM_free);
    if (params.get() == NULL) {
        throw PrivmxCryptoserviceEccPrivateKeyException("Initialization of OSSL_PARAM structure fail");
    }

    evp_pkey_ctx_unique_ptr ctx(EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL), EVP_PKEY_CTX_free);
    EVP_PKEY_CTX *ctx_raw = ctx.get();
    if (ctx_raw == NULL) {
        throw PrivmxCryptoserviceEccPrivateKeyException("Create of key context structure fail");
    }

    if (EVP_PKEY_fromdata_init(ctx_raw) <= 0) {
        throw PrivmxCryptoserviceEccPrivateKeyException("Initialization of key context structure fail");
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_fromdata(ctx_raw, &pkey, EVP_PKEY_KEYPAIR, params.get()) <= 0) {
        throw PrivmxCryptoserviceEccPrivateKeyException("Initialization of EVP_PKEY structure fail");
    }

    evp_pkey_unique_ptr result (pkey, EVP_PKEY_free);
    _evp_pkey = std::move(result);
}

/// @brief Create new private key (containing private and public keys data)
/// @param p Optional provider for symmetric cryptography operations
PrivateKey2::PrivateKey2(std::shared_ptr<ISymCryptoProvider> p) : _provider(p) {
    evp_pkey_unique_ptr pkey(EVP_EC_gen("P-256"), EVP_PKEY_free);
    _evp_pkey = std::move(pkey);
}

Bytes PrivateKey2::toRaw() const {
    EVP_PKEY *pkey = _evp_pkey.get();
    OSSL_PARAM *params_raw = NULL;
    if (EVP_PKEY_todata(pkey, EVP_PKEY_KEYPAIR, &params_raw) != 1) {
        throw PrivmxCryptoserviceEccPrivateKeyException("EVP_PKEY_todata failed");
    }
    PrivateKey2::ossl_param_unique_ptr params(params_raw,OSSL_PARAM_free);

    // Locate the specific parameter for the private key within the array
    OSSL_PARAM *ppriv = OSSL_PARAM_locate(params.get(), OSSL_PKEY_PARAM_PRIV_KEY);
    if (ppriv == NULL) {
        throw PrivmxCryptoserviceEccPrivateKeyException("Private key parameter not found");
    }

    // Locate the specific parameter for the public key within the array
    OSSL_PARAM *ppub = OSSL_PARAM_locate(params.get(), OSSL_PKEY_PARAM_PUB_KEY);
    if (ppub == NULL) {
        throw PrivmxCryptoserviceEccPrivateKeyException("Public key parameter not found");
    }

    BIGNUM *priv_raw = NULL;
    if (OSSL_PARAM_get_BN(ppriv, &priv_raw) != 1) {
        throw PrivmxCryptoserviceEccPrivateKeyException("Failed to get private key raw bytes");
    }
    PrivateKey2::bignum_unique_ptr priv(priv_raw, BN_free);

    const size_t priv_key_len = 32;
    size_t pub_key_len = 65;
    // Bytes result(32+65);
    Bytes result(priv_key_len+pub_key_len);
    unsigned char *res_priv_d = reinterpret_cast<unsigned char*>(result.data());
    unsigned char *res_pub_d = reinterpret_cast<unsigned char*>(result.data()+priv_key_len);

    if(priv_key_len != BN_bn2bin(priv.get(), res_priv_d)) {
        PrivmxCryptoserviceEccPrivateKeyException("Wrong private key size");
    } 

    if (OSSL_PARAM_get_octet_string(ppub, (void **)&res_pub_d, pub_key_len, &pub_key_len) != 1) {
        PrivmxCryptoserviceEccPrivateKeyException("Failed to get public key raw bytes");

    }
    if(pub_key_len != 65) {
        PrivmxCryptoserviceEccPrivateKeyException("Invalid public key size");
    } 

    return result;
}

Bytes PrivateKey2::toRawPublicKey() const {
    unsigned char *pubkey;
    size_t pubkey_len = EVP_PKEY_get1_encoded_public_key(_evp_pkey.get(), &pubkey);
    uint8_t *d = reinterpret_cast<uint8_t*> (pubkey);    
    Bytes result(d, d+pubkey_len);
    OPENSSL_free(pubkey);

    if (pubkey_len != 65) {
        PrivmxCryptoserviceEccPrivateKeyException("Invalid public key size");
    } 

    return result;
}

// PublicKey2 PrivateKey2::getPublicKey() const {
//     return PublicKey2(toRawPublicKey(), _provider);
// }

Bytes PrivateKey2::derive(EVP_PKEY* peerkey) const {
    // ENGINE *eng = ...;
    // ctx = EVP_PKEY_CTX_new(pkey, engine);
    evp_pkey_ctx_unique_ptr ctx(EVP_PKEY_CTX_new(_evp_pkey.get(), NULL), EVP_PKEY_CTX_free);
    EVP_PKEY_CTX *ctx_raw = ctx.get();
    if (ctx_raw == NULL) {
        PrivmxCryptoserviceEccPrivateKeyException("Failed to create key context");
    }

    if (EVP_PKEY_derive_init(ctx_raw) <= 0) {
        throw PrivmxCryptoserviceEccPrivateKeyException("Initialization of key context structure fail");
    }
    
    if (EVP_PKEY_derive_set_peer(ctx_raw, peerkey) <= 0) {
        throw PrivmxCryptoserviceEccPrivateKeyException("Setting peer key fail");
    }

    size_t skeylen;
    /* Determine buffer length */
    if (EVP_PKEY_derive(ctx_raw, NULL, &skeylen) <= 0) {
        throw PrivmxCryptoserviceEccPrivateKeyException("Determining secret share key size fail");
    }

    Bytes skey(skeylen);
    unsigned char *sk = reinterpret_cast<unsigned char *>(skey.data());

    if (EVP_PKEY_derive(ctx_raw, sk, &skeylen) <= 0) {
        throw PrivmxCryptoserviceEccPrivateKeyException("Derivation secret share key size fail");
    }

    return skey;
}

Bytes PrivateKey2::derive(const PublicKey2& peerkey) const {
    return derive(peerkey.getRawKey());
}

Bytes PrivateKey2::sign(BytesView data) const {
    /* Create the Message Digest Context */
    // evp_md_ctx_unique_ptr mdctx(EVP_MD_CTX_create(), EVP_MD_CTX_destroy);
    evp_md_ctx_unique_ptr mdctx(EVP_MD_CTX_create(), EVP_MD_CTX_free);
    EVP_MD_CTX *ctx_raw = mdctx.get();
    if (ctx_raw == NULL) {
        throw PrivmxCryptoserviceEccPrivateKeyException("Create of message digest context fail");
    }
 
    /* Initialise the DigestSign operation - SHA-256 has been selected as the message digest function */
    if(EVP_DigestSignInit(ctx_raw, NULL, EVP_sha256(), NULL, _evp_pkey.get()) != 1) {
        throw PrivmxCryptoserviceEccPrivateKeyException("Initialization of message digest context fail");
    }
    
    /* Call update with the message */
    if(EVP_DigestSignUpdate(ctx_raw, data.data(), data.size()) != 1) {
        throw PrivmxCryptoserviceEccPrivateKeyException("Update of signing message fail");
    }
    
 /* Finalise the DigestSign operation */
 /* First call EVP_DigestSignFinal with a NULL sig parameter to obtain the length of the
  * signature. Length is returned in signlen */
    size_t signlen;
    if(1 != EVP_DigestSignFinal(ctx_raw, NULL, &signlen)) {
        throw PrivmxCryptoserviceEccPrivateKeyException("Obtaining signature size fail");
    }
    // Note: the real length of signature may be lower that signlen

    /* Allocate memory for the signature based on size in signlen */
    Bytes signature(signlen);
    unsigned char *sig = reinterpret_cast<unsigned char *> (signature.data());

    if(EVP_DigestSignFinal(ctx_raw, sig, &signlen) != 1) {
        throw PrivmxCryptoserviceEccPrivateKeyException("Finalise the DigestSign operation fail");
    }

    if (signature.size() != signlen) {
        // throw PrivmxCryptoserviceEccPrivateKeyException("Signature size error: ");
        std::string msg("Signature size error: ");
        msg = msg + std::to_string(signature.size()) 
                  + " vs "
                  + std::to_string(signlen);
        if (signlen > 0 && signlen < signature.size())
            signature.resize(signlen);
        else
            throw PrivmxCryptoserviceEccPrivateKeyException(msg);
    }

    return signature;
}


Bytes PrivateKey2::deriveSharedSecret(const IPublicKey& publicKey) const {
    if (typeid(publicKey) != typeid(PublicKey2)) {
        throw PrivmxCryptoserviceEccPrivateKeyTypeKeyException("PrivateKey2::deriveSharedSecret: Wrong type of public key");
    }
    Bytes secret = derive((const PublicKey2&) publicKey);
    // return Utils::fillTo32b(secret);
    secret.resize(32);
    return secret;
}

// Bytes PrivateKey::open(BytesView sealed, const IPublicKey* expectedSender) const {
//     if (expectedSender != nullptr && typeid(*expectedSender) != typeid(PublicKey)) {
//         throw PrivmxCryptoserviceEccPrivateKeyTypeKeyException("PrivateKey::open: Wrong type of public key");
//     } else if (expectedSender != nullptr) {
//         return decrypt(sealed);
//     } else {
//         return decrypt(sealed, *((const PublicKey*) expectedSender));
//     }
// }

Bytes PrivateKey2::open(BytesView sealed, const IPublicKey* expectedSender) const {
    if (expectedSender != nullptr && typeid(*expectedSender) != typeid(PublicKey2)) {
        throw PrivmxCryptoserviceEccPrivateKeyTypeKeyException("PrivateKey2::open: Wrong type of public key");
    } else if (expectedSender != nullptr) {
        return decrypt(sealed);
    } else {
        // return decrypt(sealed, *((const PublicKey2*) expectedSender));
        return decrypt(sealed, (const PublicKey2*) expectedSender);
    }
}

Bytes PrivateKey2::export_(KeyFormat format) const {
    if (format == KeyFormat::Raw) {
        return toRaw();
    } else {
        // other formats ...
        throw PrivmxCryptoserviceEccPrivateKeyExportException("PrivateKey2::export_:: Unknown data format");
    }
}

void PrivateKey2::setSymProvider(std::shared_ptr<ISymCryptoProvider> provider) {
    _provider = provider;
}

Bytes PrivateKey2::eciesDecrypt(BytesView enc_buf, const PublicKey2& public_key) const {
    Bytes secret = derive(public_key);
    Bytes _shared_key = _provider->digest(Hash::Sha512, secret);
    Bytes _private_enc_key = toRaw();
    _private_enc_key.resize(32);

    // std::string c = enc_buf.substr(0, enc_buf.length() - 4);
    // std::string d = enc_buf.substr(enc_buf.length() - 4, 4);
    Bytes c = Bytes(enc_buf.begin(), enc_buf.end() - 4);
    Bytes d = Bytes(enc_buf.end() - 4, enc_buf.end());
    // std::string M = eciesGetM();
    // std::string M = _shared_key.substr(32, 32);
    Bytes M = Bytes(_shared_key.begin()+32, _shared_key.begin()+64);
    Bytes d2 =  _provider->hmac(Hash::Sha256, M, c);
    d2.resize(4);
    if (d != d2) {
        throw PrivmxCryptoserviceEccPrivateKeyDecryptInvalidChecksumeException("ECIES: InvalidChecksumException");
    }
    // std::string E = eciesGetE();
    // std::string E = _shared_key.substr(0, 32);
    Bytes E = Bytes(_shared_key.begin(), _shared_key.begin()+32);
    // return Utils::b2s(_provider->decrypt({SymAlg::Aes256Cbc, Utils::s2b(E), Utils::s2b(c.substr(0, 16))}, Utils::s2b(c.substr(16))));
    return _provider->decrypt({SymAlg::Aes256Cbc, E, Bytes(c.begin(),c.begin()+16)}, Bytes(c.begin()+16,c.end()));
}

// Bytes PrivateKey2::decrypt(BytesView cipher, const std::optional<PublicKey2>& pubOfSignature) const {
//     // To recheck and modify 
//     // 1. new size of public key is 65 bytes instead of 33 bytes
//     // 2. compare keys by their "raw" (octed string) representation
//     // if (cipher.front() != 101 || cipher.size() < 67) {
//     if (cipher.front() != 101 || cipher.size() < (1+65+65)) {
//         throw PrivmxCryptoserviceEccPrivateKeyInvalidFirstByteOfCipherException("EciesEncryptor: InvalidFirstByteOfCipherException");
//     }
//     // auto external_pub = cipher.substr(1, 33);
//     // auto my_pub = cipher.substr(34, 33);
//     // Bytes external_pub = Bytes(cipher.begin()+1,cipher.begin()+34);
//     // Bytes my_pub = Bytes(cipher.begin()+34,cipher.begin()+67);
//     Bytes external_pub = Bytes(cipher.begin()+1,cipher.begin()+1+65);
//     Bytes my_pub = Bytes(cipher.begin()+1+65,cipher.begin()+1+65+65);

//     // auto external_pub_ec = PublicKey::fromDER(_provider, external_pub);
//     // auto external_pub_ec = PublicKey2(external_pub, _provider);
//     PublicKey2 external_pub_ec(external_pub, _provider);
//     // TO BE REWRITED
//     // if(pubOfSignature.has_value() && external_pub_ec != pubOfSignature.value()) {
//     //     throw PrivmxCryptoserviceEccPrivateKeyDecryptSignatureException("EciesEncryptor: GivenPublicKeyDoesNotMatchWithSignatureException");
//     // }
//     if(pubOfSignature.has_value() && external_pub != pubOfSignature.value().toRaw()) {
//         throw PrivmxCryptoserviceEccPrivateKeyDecryptSignatureException("EciesEncryptor: GivenPublicKeyDoesNotMatchWithSignatureException");
//     }

//     // auto my_pub_ec = PublicKey::fromDER(_provider, my_pub);
//     // auto my_pub_ec = PublicKey2(my_pub, _provider);
//     // PublicKey2 my_pub_ec (my_pub, _provider);
//     // TO BE REWRITED
//     // if (my_pub_ec != getPublicKey()) {
//     //     throw PrivmxCryptoserviceEccPrivateKeyTypeKeyException("EciesEncryptor: GivenPrivKeyDoesNotMatchException");
//     // }
//     if (my_pub != toRawPublicKey()) {
//         throw PrivmxCryptoserviceEccPrivateKeyTypeKeyException("EciesEncryptor: GivenPrivKeyDoesNotMatchException");
//     }

//     // auto key = eciesDecrypt(cipher.substr(67), external_pub_ec);
//     // auto key = eciesDecrypt(Bytes(cipher.begin()+67,cipher.end()), external_pub_ec);
//     auto key = eciesDecrypt(Bytes(cipher.begin()+1+65+65,cipher.end()), external_pub_ec);
//     return key;
// }


Bytes PrivateKey2::decrypt(BytesView cipher, const PublicKey2 *pubOfSignature) const {
    // To recheck and modify 
    // 1. new size of public key is 65 bytes instead of 33 bytes
    // 2. compare keys by their "raw" (octed string) representation
    // if (cipher.front() != 101 || cipher.size() < 67) {
    if (cipher.front() != 101 || cipher.size() < (1+65+65)) {
        throw PrivmxCryptoserviceEccPrivateKeyInvalidFirstByteOfCipherException("EciesEncryptor: InvalidFirstByteOfCipherException");
    }
    Bytes external_pub = Bytes(cipher.begin()+1,cipher.begin()+1+65);
    Bytes my_pub = Bytes(cipher.begin()+1+65,cipher.begin()+1+65+65);

    PublicKey2 external_pub_ec(external_pub, _provider);
    if(pubOfSignature != nullptr && external_pub != pubOfSignature->toRaw()) {
        throw PrivmxCryptoserviceEccPrivateKeyDecryptSignatureException("EciesEncryptor: GivenPublicKeyDoesNotMatchWithSignatureException");
    }
    if (my_pub != toRawPublicKey()) {
        throw PrivmxCryptoserviceEccPrivateKeyTypeKeyException("EciesEncryptor: GivenPrivKeyDoesNotMatchException");
    }
    auto key = eciesDecrypt(Bytes(cipher.begin()+1+65+65,cipher.end()), external_pub_ec);
    return key;
}

Bytes PrivateKey2::decrypt(BytesView cipher) const {
    // To recheck and modify 
    // 1. new size of public key is 65 bytes instead of 33 bytes
    // 2. compare keys by their "raw" (octed string) representation
    // if (cipher.front() != 101 || cipher.size() < 67) {
    if (cipher.front() != 101 || cipher.size() < (1+65+65)) {
        throw PrivmxCryptoserviceEccPrivateKeyInvalidFirstByteOfCipherException("EciesEncryptor: InvalidFirstByteOfCipherException");
    }
    Bytes external_pub = Bytes(cipher.begin()+1,cipher.begin()+1+65);
    Bytes my_pub = Bytes(cipher.begin()+1+65,cipher.begin()+1+65+65);

    PublicKey2 external_pub_ec(external_pub, _provider);
    if (my_pub != toRawPublicKey()) {
        throw PrivmxCryptoserviceEccPrivateKeyTypeKeyException("EciesEncryptor: GivenPrivKeyDoesNotMatchException");
    }
    auto key = eciesDecrypt(Bytes(cipher.begin()+1+65+65,cipher.end()), external_pub_ec);
    return key;
}

Bytes PrivateKey2::sign(BytesView data, SigScheme scheme) const {
    // TO BE COMPLETED
    // switch (scheme) {
    //     case SigScheme::EcdsaSecp256k1CompactWithHash: // first we need to obtain hash
    //         // return Utils::s2b(_key.sign(Utils::b2s(_provider->digest(Hash::Sha256, data))));
    //         return _key.sign(_provider->digest(Hash::Sha256, data));
    //     case SigScheme::EcdsaSecp256k1Compact:  // in both cases we compute signature
    //         // return Utils::s2b(_key.sign(Utils::b2s(data)));
    //         return _key.sign(data);
    //     default:
    //         throw PrivmxCryptoserviceEccUnknownSignningSchemeException("PrivateKey::sign: Unknown signning scheme");
    //         break;        
    // }
    return sign(data);
}

std::shared_ptr<IPublicKey> PrivateKey2::publicKey() const {
    PublicKey2 key = getPublicKey();
    return std::make_shared<PublicKey2>(std::move(key));
}

} // ecc
} // cryptoservice
} // privmx
