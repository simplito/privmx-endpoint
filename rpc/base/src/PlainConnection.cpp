/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/rpc/PlainConnection.hpp>

using namespace privmx::rpc;

Poco::Dynamic::Var PlainConnection::call(const std::string& method, Poco::JSON::Object::Ptr params, const MessageSendOptionsEx& options, privmx::utils::CancellationToken::Ptr token) {
    return _connection->call(method, params, options, token, true);
}
