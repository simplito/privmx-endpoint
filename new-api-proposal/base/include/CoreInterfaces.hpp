/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTOSERVICE_CRYPTOINTERFACES_HPP_
#define _PRIVMXLIB_CRYPTOSERVICE_CRYPTOINTERFACES_HPP_

#include <vector>
#include <string>
#include <memory>
#include <span>
#include <optional>

#include "CoreTypes.hpp"

namespace privmx {
namespace cryptoservice {

// ---- 1. Random number generator ----
class IRandom {
public:
    virtual ~IRandom() = default;
    virtual Bytes randomBytes(size_t len) = 0;
};

// ---- 2. Hash ----
class IDigest {
public:
    virtual ~IDigest() = default;
    virtual Bytes digest(Hash alg, BytesView data) = 0;
};

// ---- 3. HMAC ----
class IHmac {
public:
    virtual ~IHmac() = default;
    virtual Bytes hmac(Hash alg, BytesView key, BytesView data) = 0;
};

// ---- 4. Symmetric encryption ----
class ISymmetricCipher {
public:
    virtual ~ISymmetricCipher() = default;
    virtual Bytes encrypt(const SymParams&, BytesView plaintext) = 0;  
    virtual Bytes decrypt(const SymParams&, BytesView ciphertext) = 0;
};

// ---- 5. Key derivation functions ----
class IKdf {
public:
    virtual ~IKdf() = default;
    virtual Bytes derive(const KdfParams& opt, BytesView secretData) = 0;  
};

// ---- Basic roles provider (to be injected into an asymmetric cryptography role) ----
 class ISymCryptoProvider : public IRandom, public IDigest, public IHmac, public ISymmetricCipher {};


// ---- 6. Keys in asymmetric cryptography ----

class IPrivateKey;

class IPublicKey {
public:
    virtual ~IPublicKey() = default;
    virtual bool verify(BytesView data, BytesView sig, SigScheme) const = 0;

    // previously EciesEncryptor::encrypt(*this,data,senderForSignature)
    virtual Bytes seal(BytesView data, const IPrivateKey& senderForSignature) const = 0;
    // Maybe change to the following(?):
    // virtual Bytes seal(BytesView data, const std::shared_ptr<IPublicKey>  senderForSignature) const = 0;

    virtual Bytes export_(KeyFormat) const = 0;                 // only: Der/Base58Der/Base58DerAddr

    virtual void setSymProvider(std::shared_ptr<ISymCryptoProvider>) = 0;  
};

class IPrivateKey {
public:
    virtual ~IPrivateKey() = default;
    virtual Bytes sign(BytesView data, SigScheme) const = 0;
    virtual std::shared_ptr<IPublicKey> publicKey() const = 0;

    // previously ECDHE(*this, publicKey).getSecret()
    virtual Bytes deriveSharedSecret(const IPublicKey& publicKey) const = 0;  
    // Maybe change to the following(?):
    // virtual Bytes deriveSharedSecret(const std::shared_ptr<IPublicKey> publicKey) const = 0;  

    // previously EciesEncryptor::decrypt(*this,sealed,expectedSender)
    virtual Bytes open(BytesView sealed, const IPublicKey* expectedSender = nullptr) const = 0;
    // Maybe change to the following(?):
    // virtual Bytes open(BytesView sealed, const std::shared_ptr<IPublicKey> expectedSender = nullptr) const = 0;

    virtual Bytes export_(KeyFormat) const = 0;                     // only: Wif (to add Raw?)

    virtual void setSymProvider(std::shared_ptr<ISymCryptoProvider>) = 0;  
};

class IExtKey {
public:
    virtual ~IExtKey() = default;
    virtual std::shared_ptr<IExtKey> deriveChild(uint32_t index, bool hardened) const = 0;
    virtual std::shared_ptr<IPrivateKey> privateKey() const = 0;
    virtual std::shared_ptr<IPublicKey>  publicKey()  const = 0;
    virtual Bytes chainCode() const = 0;

    virtual void setSymProvider(std::shared_ptr<ISymCryptoProvider>) = 0;  
};

 // ---- 7. Key provider ----
class IKeyProvider {
public:
    virtual ~IKeyProvider() = default;
    virtual std::shared_ptr<IPrivateKey> generatePrivateKey(AsymAlg = AsymAlg::EccSecp256k1) = 0;
    virtual std::shared_ptr<IPrivateKey> importPrivateKey(BytesView, KeyFormat, AsymAlg = AsymAlg::EccSecp256k1) = 0;
    virtual std::shared_ptr<IPublicKey>  importPublicKey (BytesView, KeyFormat, AsymAlg = AsymAlg::EccSecp256k1) = 0;
    virtual std::shared_ptr<IExtKey>     extKeyFromSeed(BytesView seed, AsymAlg = AsymAlg::EccSecp256k1) = 0;
// or below:
    virtual std::shared_ptr<IExtKey>  importExtKey (BytesView, KeyFormat, AsymAlg = AsymAlg::EccSecp256k1) = 0;
};

// ---- Provider facade (role aggregate) ----
class ICryptoProvider : public ISymCryptoProvider, public IKdf, public IKeyProvider
{
public:
    virtual std::string name() const = 0;         
    virtual uint32_t    version() const = 0;

    virtual ~ICryptoProvider() = default;
};


} // cryptoservice
} // privmx

#endif // _PRIVMXLIB_CRYPTOSERVICE_CRYPTOINTERFACES_HPP_