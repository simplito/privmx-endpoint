/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTO_CRYPTOPRIVMX_HPP_
#define _PRIVMXLIB_CRYPTO_CRYPTOPRIVMX_HPP_

#include <string>

namespace privmx {
namespace crypto {

/**
 * Reading the pre-3.0.0 frame. **Reading only** — nothing writes it any more.
 *
 * `privmxEncrypt` and its option presets are gone with the last caller. The one frame this library
 * still has to open is what `CryptoApi::encryptDataSymmetric` handed callers through 2.x: those bytes
 * do not live on the bridge, so there is no container to migrate and no second chance at them.
 * Everything written from now on is a suite-tagged `core::CryptoSuite` frame.
 */
class CryptoPrivmx
{
public:
    static std::string privmxDecrypt(bool is_signed, const std::string& data, const std::string& key32, const std::string& iv16 = std::string(), size_t taglen = 16);
    static std::string privmxDecrypt(const std::string& data, const std::string& key32, const std::string& iv16 = std::string(), size_t taglen = 16);
};

} // crypto
} // privmx

#endif // _PRIVMXLIB_CRYPTO_CRYPTOPRIVMX_HPP_
