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
