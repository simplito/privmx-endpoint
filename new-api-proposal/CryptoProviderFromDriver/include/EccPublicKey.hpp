/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTOSERVICE_FROMDRIVER_ECCPUBLICKEY_HPP_
#define _PRIVMXLIB_CRYPTOSERVICE_FROMDRIVER_ECCPUBLICKEY_HPP_

#include "CoreTypes.hpp"
#include "CoreInterfaces.hpp"

namespace privmx {
namespace cryptoservice {
    
class EccPublicKey : IPublicKey {
public:
    virtual ~EccPublicKey() = default;
    virtual bool  verify(BytesView data, BytesView sig, SigScheme) const = 0;
    virtual Bytes export_(KeyFormat) const = 0;                 // np. Der/Base58Der



};


} // cryptoservice
} // privmx

#endif // _PRIVMXLIB_CRYPTOSERVICE_FROMDRIVER_ECCPUBLICKEY_HPP_