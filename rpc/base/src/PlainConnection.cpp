#include <privmx/rpc/PlainConnection.hpp>

using namespace privmx::rpc;

Poco::Dynamic::Var PlainConnection::call(const std::string& method, Poco::JSON::Object::Ptr params, const MessageSendOptionsEx& options, privmx::utils::CancellationToken::Ptr token) {
    return _connection->call(method, params, options, token, true);
}
