/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_RPC_CONTENTTYPE_HPP_
#define _PRIVMXLIB_RPC_CONTENTTYPE_HPP_

#include <Poco/Types.h>

namespace privmx {
namespace rpc {

class ContentType
{
public:
    static const Poco::UInt8 CHANGE_CIPHER_SPEC = 20;
    static const Poco::UInt8 ALERT              = 21;
    static const Poco::UInt8 HANDSHAKE          = 22;
    static const Poco::UInt8 APPLICATION_DATA   = 23; 
};

} // rpc
} // privmx

#endif // _PRIVMXLIB_RPC_CONTENTTYPE_HPP_
