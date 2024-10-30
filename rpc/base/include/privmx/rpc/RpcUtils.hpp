#ifndef _PRIVMXLIB_RPCUTILS_HPP_
#define _PRIVMXLIB_RPCUTILS_HPP_

#include <regex>
#include <string>

namespace privmx {
namespace rpc {

class RpcUtils
{
public:
    static bool isValidHostname(const std::string& hostname);

private:
    static const std::regex HOSTNAME_REGEX;
};

} // rpc
} // privmx

#endif // _PRIVMXLIB_RPCUTILS_HPP_
