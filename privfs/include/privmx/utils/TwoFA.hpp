#ifndef _PRIVMXLIB_UTILS_TWOFA_HPP_
#define _PRIVMXLIB_UTILS_TWOFA_HPP_

#include <Poco/JSON/Object.h>

namespace privmx {
namespace utils {

class TwoFA
{
public:
    static Poco::JSON::Object::Ptr generateToken(const std::string& secret);
    static Poco::JSON::Object::Ptr generateToken(const Poco::JSON::Object::Ptr data);
};

} // utils
} // privmx

#endif // _PRIVMXLIB_UTILS_TWOFA_HPP_
