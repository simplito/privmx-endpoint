/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_RPC_POCO_UTILS_HTTPCLIENTSESSIONFACTORY_HPP_
#define _PRIVMXLIB_RPC_POCO_UTILS_HTTPCLIENTSESSIONFACTORY_HPP_

#include <Poco/Net/HTTPSClientSession.h>
#include <Poco/SharedPtr.h>
#include <Poco/URI.h>

namespace privmx {
namespace rpc {
namespace pocoimpl {

class HTTPClientSessionFactory
{
public:
    static Poco::SharedPtr<Poco::Net::HTTPClientSession> create(const Poco::URI& uri);
};

} // pocoimpl
} // utils
} // privmx

#endif // _PRIVMXLIB_RPC_POCO_UTILS_HTTPCLIENTSESSIONFACTORY_HPP_
