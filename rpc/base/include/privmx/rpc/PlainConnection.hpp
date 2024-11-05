/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_RPC_PLAINCONNECTION_HPP_
#define _PRIVMXLIB_RPC_PLAINCONNECTION_HPP_

#include <privmx/rpc/AuthorizedConnection.hpp>

namespace privmx {
namespace rpc {

class PlainConnection
{
public:
    using Ptr = Poco::SharedPtr<PlainConnection>;

    PlainConnection(AuthorizedConnection::Ptr connection) : _connection(connection) {}
    Poco::Dynamic::Var call(const std::string& method, Poco::JSON::Object::Ptr params, const MessageSendOptionsEx& options = MessageSendOptionsEx(), privmx::utils::CancellationToken::Ptr token = privmx::utils::CancellationToken::create());

private:
    AuthorizedConnection::Ptr _connection;
};

} // rpc
} // privmx

#endif // _PRIVMXLIB_RPC_PLAINCONNECTION_HPP_
