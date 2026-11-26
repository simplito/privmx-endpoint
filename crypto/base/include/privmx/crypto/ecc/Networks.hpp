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

namespace privmx {
namespace crypto {

/// The two version bytes a WIF and a Base58 address carry. The xprv/xpub pair that used to sit
/// beside them went with the legacy `ExtKey`: pmx-crypto serialises extended keys in its own
/// envelope, which names the algorithm instead of assuming one curve.
struct Networks
{
    struct Network
    {
        const char PUB_KEY_HASH;
        const char WIF;
    };
    static const Network BITCOIN;
};

} // crypto
} // privmx

#endif // _PRIVMXLIB_CRYPTO_NETWORKS_HPP_
