/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

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
