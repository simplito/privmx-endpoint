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

// #include "ECC.hpp"
#include "PublicKey2.hpp"
#include "PrivateKey2.hpp"
// #include "Networks.hpp"
// #include "Base58.hpp"
// #include "Utils.hpp"

#include "EccExceptions.hpp"

namespace privmx {
namespace cryptoservice {
namespace ecc {

/// @brief Create public key from public key data
/// @param rawdata Raw 65 bytes of public key data
/// @param p Optional provider for symmetric cryptography operations
PublicKey2::PublicKey2(BytesView rawdata, std::shared_ptr<ISymCryptoProvider> p) 
                        : _provider(p) {
    if (rawdata.size() != 65) {
        throw PrivmxCryptoserviceEccPrivateKeyException("Incorrect input data size");
    }
    const unsigned char *pub_data = reinterpret_cast<const unsigned char*>(rawdata.data());

    PublicKey2::ossl_param_bld_unique_ptr param_bld(OSSL_PARAM_BLD_new(),OSSL_PARAM_BLD_free);
    OSSL_PARAM_BLD *param_bld_raw = param_bld.get();
    if (param_bld_raw == NULL) {
        throw PrivmxCryptoserviceEccPrivateKeyException("Initialization of OSSL_PARAM_BLD structure fail");
    }

    if (OSSL_PARAM_BLD_push_utf8_string(param_bld_raw, "group",
                                           "prime256v1", 0) == 0) {
        throw PrivmxCryptoserviceEccPrivateKeyException("Setting curve group fail");
    }

    if (OSSL_PARAM_BLD_push_octet_string(param_bld_raw, "pub",
                                            pub_data, 65) == 0) {
        throw PrivmxCryptoserviceEccPrivateKeyException("Setting key public part fail");
    }

    PublicKey2::ossl_param_unique_ptr params(OSSL_PARAM_BLD_to_param(param_bld_raw),OSSL_PARAM_free);
    if (params.get() == NULL) {
        throw PrivmxCryptoserviceEccPrivateKeyException("Initialization of OSSL_PARAM structure fail");
    }

    PublicKey2::evp_pkey_ctx_unique_ptr ctx(EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL), EVP_PKEY_CTX_free);
    EVP_PKEY_CTX *ctx_raw = ctx.get();
    if (ctx_raw == NULL) {
        throw PrivmxCryptoserviceEccPrivateKeyException("Create of key context structure fail");
    }

    if (EVP_PKEY_fromdata_init(ctx_raw) <= 0) {
        throw PrivmxCryptoserviceEccPrivateKeyException("Initialization of key context structure fail");
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_fromdata(ctx_raw, &pkey, EVP_PKEY_PUBLIC_KEY, params.get()) <= 0) {
        throw PrivmxCryptoserviceEccPrivateKeyException("Initialization of EVP_PKEY structure fail");
    }

    evp_pkey_unique_ptr result (pkey, EVP_PKEY_free);
    // std::shared_ptr<EVP_PKEY> result (pkey);
    _evp_pkey = std::move(result);
}

Bytes PublicKey2::toRaw() const {
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

EVP_PKEY* PublicKey2::getRawKey() const {
    return _evp_pkey.get();
}

bool PublicKey2::verify(BytesView data, BytesView signature) const {
    evp_md_ctx_unique_ptr mdctx(EVP_MD_CTX_create(), EVP_MD_CTX_free);
    EVP_MD_CTX *ctx_raw = mdctx.get();
    if (ctx_raw == NULL) {
        throw PrivmxCryptoserviceEccPrivateKeyException("Create of message digest context fail");
    }
 
    /* Initialise the DigestSign operation - SHA-256 has been selected as the message digest function */
    if(EVP_DigestVerifyInit(ctx_raw, NULL, EVP_sha256(), NULL, _evp_pkey.get()) != 1) {
        throw PrivmxCryptoserviceEccPrivateKeyException("Initialization of message digest context fail");
    }

    /* Call update with the message */
    if(EVP_DigestVerifyUpdate(ctx_raw, data.data(), data.size()) != 1) {
        throw PrivmxCryptoserviceEccPrivateKeyException("Update of signed message fail");
    }

    return EVP_DigestVerifyFinal(ctx_raw, signature.data(), signature.size()) == 1;
}

Bytes PublicKey2::encrypt(BytesView data, const PrivateKey2& privForSignature) const {
    Bytes cipher = eciesEncrypt(data, privForSignature);
    // return std::string("e")
    //         .append(privForSignature.getPublicKey().toDER())
    //         .append(toDER())
    //         .append(cipher);
    // Bytes pub = Utils::s2b(privForSignature.getPublicKey().toDER());
    // Bytes pub = privForSignature.getPublicKey().toDERb();
    Bytes pub = privForSignature.toRawPublicKey();
    // Bytes priv = Utils::s2b(toDER());
    // Bytes priv = toDERb();
    Bytes priv = toRaw();
    // priv.resize(32);
    Bytes e(1, (uint8_t)'e'); // probably to be replaced with const POINT_CONVERSION_UNCOMPRESSED
    e.reserve(1 + cipher.size() + pub.size() + priv.size()); 
    e.insert(e.end(),pub.begin(),pub.end());   // pub.size()  == 65
    e.insert(e.end(),priv.begin(),priv.end()); // priv.size() == 65
    e.insert(e.end(),cipher.begin(),cipher.end());
    // // temporary - for testing only
    // std::string msg("sizes: type = 1, pub = ");
    // msg = msg + std::to_string(pub.size())
    //      + ", priv = " + std::to_string(priv.size())
    //      + ", cipher = " + std::to_string(cipher.size());
    // throw PrivmxCryptoserviceEccKeyProviderException(msg);
    return e;
}

// new variant from ECIES class:
Bytes PublicKey2::eciesEncrypt(BytesView data, const PrivateKey2& private_key) const {
    Bytes secret = private_key.derive(*this);
    Bytes _shared_key = _provider->digest(Hash::Sha512,secret);
    Bytes _private_enc_key = private_key.toRaw();
    _private_enc_key.resize(32);

    Bytes iv = _provider->hmac(Hash::Sha256, _private_enc_key, data);
    iv.resize(16);
    // std::string M = getM();
    // std::string M = _shared_key.substr(32, 32);
    Bytes M(_shared_key.begin()+32, _shared_key.begin()+64);
    // std::string E = getE();
    // std::string E = _shared_key.substr(0, 32);
    Bytes E(_shared_key.begin(), _shared_key.begin()+32);
    // std::string c = iv + Utils::b2s(_provider->encrypt({SymAlg::Aes256Cbc, Utils::s2b(E), Utils::s2b(iv)}, Utils::s2b(data)));
    Bytes ciphertext = _provider->encrypt({SymAlg::Aes256Cbc, E, iv}, data);
    Bytes c(iv.begin(),iv.end());
    c.reserve(c.size()+ciphertext.size()+4);
    c.insert(c.end(),ciphertext.begin(),ciphertext.end());
    // return c + Utils::b2s(_provider->hmac(Hash::Sha256,Utils::s2b(M), Utils::s2b(c))).substr(0, 4);
    Bytes h = _provider->hmac(Hash::Sha256,M, c);
    c.insert(c.end(),h.begin(),h.begin()+4);
    return c;
}

bool PublicKey2::verify(BytesView data, BytesView signature, SigScheme scheme) const {
    // TO BE COMPLETED
    // switch (scheme) {
    // case SigScheme::EcdsaSecp256k1Compact:
    //     // return verifyCompactSignature(Utils::b2s(data), Utils::b2s(signature));
    //     return verifyCompactSignature(data, signature);
    // case SigScheme::EcdsaSecp256k1CompactWithHash:
    //     // return verifyCompactSignatureWithHash(Utils::b2s(data), Utils::b2s(signature));
    //     return verifyCompactSignatureWithHash(data, signature);
    // default:
    //     throw PrivmxCryptoserviceEccPublicKeyUnknownSignShmException("PublicKey::verify: Unknown signing scheme");
    //     break;
    // }
    return verify(data, signature);
}

Bytes PublicKey2::seal(BytesView data, const IPrivateKey& senderForSignature) const {
    // previously EciesEncryptor::encrypt(*this,data,senderForSignature)
    if (typeid(senderForSignature) != typeid(PrivateKey2)) {
        throw PrivmxCryptoserviceEccPublicKeyTypeKeyException("PublicKey2::seal: Wrong type of private key");
    }
    return encrypt(data, (const PrivateKey2&) senderForSignature);
}


Bytes PublicKey2::export_(KeyFormat format) const {
     if (format == KeyFormat::Raw) {
        return toRaw();
    // } else if (format ==  KeyFormat::Wif) {
    //     throw PrivmxCryptoserviceEccPublicKeyExportFormatException("PrivateKey::export_: Format WIF is used only for private keys");    
    // } else if (format == KeyFormat::Der) {
    //     // return Utils::s2b(toDER());   // TO BE REPLACED
    //     return toDERb();
    // } else if (format ==  KeyFormat::Base58Der) {
    //     // return Utils::s2b(toBase58DER());   // TO BE REPLACED
    //     return toBase58DERb();
    // } else if (format ==  KeyFormat::Base58DerAddr) {
    //     return Utils::s2b(toBase58Address());   // TO BE REPLACED
    //     // return toBase58AddressB();
    } else {
        // other formats ...
        throw PrivmxCryptoserviceEccPublicKeyExportFormatException("PrivateKey2::export_: Unknown data format");    
    }
    // throw PrivmxCryptoserviceEccPublicKeyExportFormatException("PrivateKey2::export_: NOT IMPLEMENTED");
}

void PublicKey2::setSymProvider(std::shared_ptr<ISymCryptoProvider> provider) {
    _provider = provider;
}

} // ecc
} // cryptoservice
} // privmx
