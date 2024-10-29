#ifndef _PRIVMXLIB_RPC_CLIENTENDPOINT_HPP_
#define _PRIVMXLIB_RPC_CLIENTENDPOINT_HPP_

#include <future>
#include <map>
#include <sstream>
#include <Poco/Dynamic/Var.h>
#include <Poco/JSON/Object.h>
#include <Poco/Types.h>
#include <Pson/Encoder.hpp>

#include <privmx/rpc/tls/ConnectionClient.hpp>
#include <privmx/rpc/tls/TicketsManager.hpp>

namespace privmx {
namespace rpc {

class ClientEndpoint
{
public:
    static const Poco::Int32 TICKETS_MAX_COUNT = 256;
    static const Poco::Int32 TICKETS_MIN_COUNT = 3;

    ClientEndpoint(TicketsManager& tickets_manager, const ConnectionOptionsFull& options);
    std::future<Poco::Dynamic::Var> call(const std::string& method, const Poco::Dynamic::Var& params = Poco::JSON::Object::Ptr(new Poco::JSON::Object()), bool force_plain = false);
    void flush();

    TicketsManager& tickets_manager;
    std::stringstream request_buff;
    ConnectionClient connection;

private:
    void invoke(const Poco::Dynamic::Var& application_data);

    std::unique_lock<std::mutex> _request_lock;
    Pson::Encoder _pson_encoder;
    std::map<int, std::promise<Poco::Dynamic::Var>> _promises;
    bool _ticket_handshake = false;
    int _id = 0;
};

} // rpc
} // privmx

#endif // _PRIVMXLIB_RPC_CLIENTENDPOINT_HPP_
