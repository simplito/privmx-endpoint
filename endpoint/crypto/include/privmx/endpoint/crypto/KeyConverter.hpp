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
};

} // crypto
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_CRYPTO_KEYCONVERTER_HPP_
