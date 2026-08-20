/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTOSERVICE_CRYPTOPROVIDERFROMDRIVER_HPP_
#define _PRIVMXLIB_CRYPTOSERVICE_CRYPTOPROVIDERFROMDRIVER_HPP_

// #include <memory>
#include "CoreTypes.hpp"
#include "CoreInterfaces.hpp"


namespace privmx {
namespace cryptoservice {

class CryptoProviderFromDriver : public privmx::cryptoservice::ICryptoProvider, public std::enable_shared_from_this<CryptoProviderFromDriver>
{
public:
    virtual uint32_t version() const override; 
    virtual std::string name() const override;
    virtual Bytes randomBytes(size_t len) override;
    virtual Bytes digest(Hash alg, BytesView data) override; 
    virtual Bytes hmac(Hash alg, BytesView key, BytesView data) override;
    virtual Bytes encrypt(const SymParams&, BytesView plaintext) override;
    virtual Bytes decrypt(const SymParams&, BytesView ciphertext) override;
    virtual Bytes derive(const KdfParams& opt, BytesView secretData) override;  
    virtual std::shared_ptr<IPrivateKey> generatePrivateKey(AsymAlg = AsymAlg::EccSecp256k1) override;
    virtual std::shared_ptr<IPrivateKey> importPrivateKey(BytesView, KeyFormat, AsymAlg = AsymAlg::EccSecp256k1) override;
    virtual std::shared_ptr<IPublicKey>  importPublicKey (BytesView, KeyFormat, AsymAlg = AsymAlg::EccSecp256k1) override;
    virtual std::shared_ptr<IExtKey>     extKeyFromSeed(BytesView seed, AsymAlg = AsymAlg::EccSecp256k1) override;
    virtual std::shared_ptr<IExtKey>     importExtKey (BytesView, KeyFormat, AsymAlg = AsymAlg::EccSecp256k1) override;

protected:
    class EccPublicKey;
    class EccPrivateKey;
    virtual Bytes digestConfStr(const char *config, BytesView data); 
    virtual Bytes hmacConfStr(const char *config,  BytesView key, BytesView data);
    virtual Bytes encryptConfStr(const char *alg, const bool padding, 
                        BytesView key, BytesView iv, BytesView plaintext);
    virtual Bytes encryptAeadConfStr(const char *alg, BytesView aad, 
                        BytesView key, BytesView iv, BytesView plaintext);
    virtual Bytes decryptConfStr(const char *alg, const bool padding, 
                        BytesView key, BytesView iv, BytesView ciphertext);
    virtual Bytes decryptAeadConfStr(const char *alg, BytesView aad, 
                        BytesView key, BytesView iv, BytesView ciphertext);

private:
    virtual Bytes pbkdf2(BytesView pass, BytesView salt, int rounds, 
                        size_t length, const char* hash);
    virtual Bytes kdf(size_t length, BytesView key, const std::string& label, Hash hash);
    virtual Bytes prf_tls12(BytesView key, BytesView seed, size_t length, Hash hash);
    virtual std::tuple<Bytes, Bytes> getKEM(BytesView key, Hash hash, size_t kelen = 32, 
                        size_t kmlen = 32);

    // return the name used in the OpenSSL functions 
    const char* getHashAlgName(Hash alg);

    // Probably not used
    // virtual Bytes generateIv(BytesView& key, Poco::Int32 idx); // require Poco
    virtual Bytes generateIv(BytesView& key, int32_t idx); 
    // 
    // methods used in bridge and endpint respectively
    // are considered to be invoked by hmac()
    virtual Bytes aes256CbcHmac256Encrypt(BytesView data, BytesView key32, Bytes iv, 
                        size_t taglen);
    virtual Bytes aes256CbcHmac256Decrypt(Bytes data, BytesView key32, size_t taglen);
    // 
    // Methods created for binary compatibility (and replacing calls from "POCO")
    // with the intention of quickly replacing functions from OPENSSL >= 3
    // 
    // to be replaced by OPENSSL_store_u32_be after migration to OPENSSL >= 3.5
    unsigned char* store_u32_be(unsigned char* out, uint32_t val); 
};

} // cryptoservice
} // privmx

#endif // _PRIVMXLIB_CRYPTOSERVICE_CRYPTOPROVIDERFROMDRIVER_HPP_