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
