/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

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
