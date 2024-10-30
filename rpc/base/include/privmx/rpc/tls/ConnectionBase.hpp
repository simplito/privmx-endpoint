#ifndef _PRIVMXLIB_RPC_CONNECTIONBASE_HPP_
#define _PRIVMXLIB_RPC_CONNECTIONBASE_HPP_

#include <functional>
#include <iostream>
#include <vector>
#include <Poco/Dynamic/Var.h>
#include <Poco/Logger.h>
#include <Poco/Types.h>
#include <Pson/Decoder.hpp>

#include <privmx/rpc/tls/ContentType.hpp>
#include <privmx/rpc/tls/RWState.hpp>

namespace privmx {
namespace rpc {

class ConnectionBase
{
public:
    struct StatePair {
        RWState read_state;
        RWState write_state;
    };
    struct StatePairCS {
        RWState client_state;
        RWState server_state;
    };

    static const std::vector<std::string> DICT;

    ConnectionBase(std::ostream& output);
    void send(const std::string& packet, Poco::UInt8 content_type = ContentType::APPLICATION_DATA, bool force_plaintext = false);
    void process(std::istream& input);
    void restoreState(const std::string& ticket_id, const std::string& master_secret, const std::string& client_random);
    void changeCipherSpec();
    StatePair getFreshRWStates(const std::string& master_secret, const std::string& client_random, const std::string& server_random);
    void setPreMasterSecret(const std::string& pre_master_secret);

    std::function<void(const Poco::Dynamic::Var&)> application_handler;

protected:
    virtual void processHandshakePacket(const Poco::Dynamic::Var& packet) = 0;
    virtual StatePair getFreshRWStatesFromParams(const StatePairCS& pair) = 0;

    const Poco::UInt8 _version = 1;
    std::ostream& _output;
    RWState _write_state;
    RWState _read_state;
    RWState _next_write_state;
    RWState _next_read_state;
    std::string _client_random;
    std::string _server_random;
    std::string _master_secret;

private:
    Pson::Decoder _pson_decoder;
};

} // rpc
} // privmx

#endif // _PRIVMXLIB_RPC_CONNECTIONBASE_HPP_
