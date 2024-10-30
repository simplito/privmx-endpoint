#ifndef _PRIVMXLIB_CRYPTO_PASSWORDMIXER_HPP_
#define _PRIVMXLIB_CRYPTO_PASSWORDMIXER_HPP_

#include <string>
#include <Poco/Dynamic/Var.h>

namespace privmx {
namespace crypto {

class PasswordMixer {
public:
    static std::string mix(const std::string& password, const Poco::Dynamic::Var& data);
    static std::tuple<std::string, Poco::JSON::Object::Ptr> generatePbkdf2(const std::string &password);
    static std::string serializeData(Poco::JSON::Object::Ptr data);
};

} // crypto
} // privmx

#endif // _PRIVMXLIB_CRYPTO_PASSWORDMIXER_HPP_
