#ifndef _PRIVMXLIB_CRYPTO_UTILS_BASE58_HPP_
#define _PRIVMXLIB_CRYPTO_UTILS_BASE58_HPP_

#include <string>

namespace privmx {
namespace utils {

class Base58
{
public:
    static std::string encode(const std::string& s);
    static std::string decode(const std::string& s);
    static std::string encodeWithChecksum(const std::string& s);
    static std::string decodeWithChecksum(const std::string& s);
    static bool is(const std::string& s);
private:
    static std::string gmp2bitcoin(std::string s);
    static std::string bitcoin2gmp(std::string s);
};

} // utils
} // privmx

#endif // _PRIVMXLIB_CRYPTO_UTILS_BASE58_HPP_
