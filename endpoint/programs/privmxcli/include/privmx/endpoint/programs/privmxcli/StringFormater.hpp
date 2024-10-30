#ifndef _PRIVMXLIB_ENDPOINT_PRIVMXCLI_STRING_FORMATER_HPP
#define _PRIVMXLIB_ENDPOINT_PRIVMXCLI_STRING_FORMATER_HPP

#include <iostream>
#include <string>

namespace privmx {
namespace endpoint {
namespace privmxcli {

class StringFormater {
public:
    static std::ostream& toCPP(std::ostream& stream, const std::string &s);
    static std::ostream& toPython(std::ostream& stream, const std::string &s);
};


} // privmxcli
} // endpoint
} // privmx


#endif // _PRIVMXLIB_ENDPOINT_PRIVMXCLI_COLORS_HPP