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


// ---- Provider facade (role aggregate) ----
class ICryptoProvider : public IRandom
            , public IDigest
            , public IHmac
            , public ISymmetricCipher 
            , public IKdf
            // , public IKeyProvider
            // , public IHybridSeal
            // // ...
{
public:
    virtual std::string name() const = 0;         
    virtual uint32_t    version() const = 0;

    virtual ~ICryptoProvider() = default;
};


} // cryptoservice
} // privmx

#endif // _PRIVMXLIB_CRYPTOSERVICE_CRYPTOINTERFACES_HPP_