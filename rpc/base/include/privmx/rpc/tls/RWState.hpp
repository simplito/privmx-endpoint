/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_RPC_RWSTATE_HPP_
#define _PRIVMXLIB_RPC_RWSTATE_HPP_

#include <string>
#include <Poco/Types.h>

namespace privmx {
namespace rpc {

class RWState
{
public:
    RWState() {}
    RWState(const std::string& key, const std::string& mac_key) : key(key), mac_key(mac_key) {}
    bool initialized() const { return !key.empty() && !mac_key.empty(); };

    std::string key;
    std::string mac_key;
    Poco::UInt64 sequence_number = 0;
};

} // rpc
} // privmx

#endif // _PRIVMXLIB_RPC_RWSTATE_HPP_
