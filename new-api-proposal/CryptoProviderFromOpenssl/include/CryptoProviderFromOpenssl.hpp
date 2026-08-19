/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTOSERVICE_CRYPTOPROVIDERFROMOPENSSL_HPP_
#define _PRIVMXLIB_CRYPTOSERVICE_CRYPTOPROVIDERFROMOPENSSL_HPP_

#include "CoreTypes.hpp"
#include "CoreInterfaces.hpp"

namespace privmx {
namespace cryptoservice {

class CryptoProviderFromOpenssl : public privmx::cryptoservice::ICryptoProvider
{
public:
    virtual uint32_t version() const override; 
    virtual std::string name() const override;
    virtual Bytes randomBytes(size_t len) override;
    virtual Bytes digest(Hash alg, BytesView data) override; 
    virtual Bytes hmac(Hash alg, BytesView key, BytesView data) override;
    virtual Bytes encrypt(const SymParams&, BytesView plaintext) override;
    virtual Bytes decrypt(const SymParams&, BytesView ciphertext) override;
// NOT IMPLEMENTED :
    virtual Bytes derive(const KdfParams& opt, BytesView secretData) override;
    virtual std::shared_ptr<IPrivateKey> generatePrivateKey(AsymAlg = AsymAlg::EccSecp256k1) override;
    virtual std::shared_ptr<IPrivateKey> importPrivateKey(BytesView, KeyFormat, AsymAlg = AsymAlg::EccSecp256k1) override;
    virtual std::shared_ptr<IPublicKey>  importPublicKey (BytesView, KeyFormat, AsymAlg = AsymAlg::EccSecp256k1) override;
    virtual std::shared_ptr<IExtKey>     extKeyFromSeed(BytesView seed, AsymAlg = AsymAlg::EccSecp256k1) override;
    virtual std::shared_ptr<IExtKey>     importExtKey (BytesView, KeyFormat, AsymAlg = AsymAlg::EccSecp256k1) override;
// protected:
//     virtual Bytes digestConfStr(const char *config, BytesView data); 
//     virtual Bytes hmacConfStr(const char *config,  BytesView key, BytesView data);

};


} // cryptoservice
} // privmx

#endif // _PRIVMXLIB_CRYPTOSERVICE_CRYPTOPROVIDERFROMOPENSSL_HPP_