/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTOSERVICE_FROMDRIVER_ECCPRIVATEKEY_HPP_
#define _PRIVMXLIB_CRYPTOSERVICE_FROMDRIVER_ECCPRIVATEKEY_HPP_

#include "CoreTypes.hpp"
#include "CoreInterfaces.hpp"
#include "EccPublicKey.hpp"


namespace privmx {
namespace cryptoservice {

class EccPrivateKey : IPrivateKey{
public:
    virtual ~EccPrivateKey() = default;
    virtual Bytes sign(BytesView data, SigScheme) const = 0;
    virtual std::shared_ptr<IPublicKey> publicKey() const = 0;
    virtual Bytes deriveSharedSecret(const IPublicKey&) const = 0;  // ECDH — zamiast ECDHE
    virtual Bytes export_(KeyFormat) const = 0;                     // Raw / Wif



};

} // cryptoservice
} // privmx

#endif // _PRIVMXLIB_CRYPTOSERVICE_FROMDRIVER_ECCPRIVATEKEY_HPP_