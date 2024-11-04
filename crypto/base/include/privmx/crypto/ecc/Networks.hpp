/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTO_NETWORKS_HPP_
#define _PRIVMXLIB_CRYPTO_NETWORKS_HPP_

#include <Poco/Types.h>

namespace privmx {
namespace crypto {

struct Networks
{
    struct Network
    {
        const struct {
            const Poco::UInt32 PUBLIC;
            const Poco::UInt32 PRIVATE;
        } BIP39;
        const char PUB_KEY_HASH;
        const char WIF;
    };
    static const Network BITCOIN;
};

} // crypto
} // privmx

#endif // _PRIVMXLIB_CRYPTO_NETWORKS_HPP_
