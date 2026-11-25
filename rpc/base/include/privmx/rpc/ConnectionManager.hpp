/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_RPC_CONNECTIONMANAGER_HPP_
#define _PRIVMXLIB_RPC_CONNECTIONMANAGER_HPP_

#include <Poco/SharedPtr.h>

#include <privmx/rpc/AuthorizedConnection.hpp>
#include <privmx/rpc/PlainConnection.hpp>

namespace privmx {
namespace rpc {

class ConnectionManager
{
public:
    using Ptr = Poco::SharedPtr<ConnectionManager>;

    static ConnectionManager::Ptr getInstance();
    AuthorizedConnection::Ptr createEcdheConnection(const EcdheOptions& auth, const ConnectionOptions& options);
    AuthorizedConnection::Ptr createEcdhexConnection(const EcdhexOptions& auth, const ConnectionOptions& options);
    PlainConnection::Ptr createPlainConnection(const ConnectionOptions& options);
    void probe(const std::string& url, long timeout = 10000);

    // TODO: make private
    static ConnectionOptionsFull fillOptions(const ConnectionOptions& options);

private:
    static ConnectionManager::Ptr _instance;
};

} // rpc
} // privmx

#endif // _PRIVMXLIB_RPC_CONNECTIONMANAGER_HPP_
