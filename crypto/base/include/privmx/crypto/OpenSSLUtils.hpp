/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTO_OPENSSLUTILS_HPP_
#define _PRIVMXLIB_CRYPTO_OPENSSLUTILS_HPP_

#include <string>

namespace privmx {
namespace crypto {

class OpenSSLUtils
{
public:
    static std::string CaLocation;

    static void handleErrors(const std::string& msg = std::string());

};

} // crypto
} // privmx

#endif // _PRIVMXLIB_CRYPTO_OPENSSLUTILS_HPP_
