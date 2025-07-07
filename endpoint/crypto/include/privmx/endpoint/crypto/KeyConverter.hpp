/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CRYPTO_KEYCONVERTER_HPP_
#define _PRIVMXLIB_ENDPOINT_CRYPTO_KEYCONVERTER_HPP_

#include <string>

namespace privmx {
namespace endpoint {
namespace crypto {

class KeyConverter
{
public:
    static std::string cryptoKeyConvertPEMToWIF(const std::string& keyPEM);
    static std::string cryptoKeyConvertPGPToBase58DER(const std::string& keyPGP);
};

} // crypto
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_CRYPTO_KEYCONVERTER_HPP_
