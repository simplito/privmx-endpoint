#ifndef _PRIVMXLIB_RPC_DRVNETCONFIG_HPP_
#define _PRIVMXLIB_RPC_DRVNETCONFIG_HPP_

#include <string>

namespace privmx {
namespace rpc {

class DrvNetConfig
{
public:
    static void setConfig(const std::string& config);

};

} // rpc
} // privmx

#endif // _PRIVMXLIB_RPC_DRVNETCONFIG_HPP_
