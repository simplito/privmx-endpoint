#ifndef _PRIVMXLIB_RPC_POCO_WEBSOCKETCHANNEL_HPP_
#define _PRIVMXLIB_RPC_POCO_WEBSOCKETCHANNEL_HPP_

#include <chrono>
#include <future>
#include <functional>
#include <istream>
#include <unordered_map>
#include <Poco/Net/WebSocket.h>

#include <privmx/rpc/channel/WebSocketChannel.hpp>
#include <privmx/rpc/channel/WebSocketNotify.hpp>
#include <privmx/utils/Types.hpp>
#include <privmx/utils/CancellationToken.hpp>

namespace privmx {
namespace rpc {
namespace pocoimpl {

class WebSocketChannel : public privmx::rpc::WebSocketChannel
{
public:
    using Ptr = Poco::SharedPtr<WebSocketChannel>;

    WebSocketChannel(const Poco::URI& uri, WebSocketNotify::Ptr notify);
    ~WebSocketChannel() override;
    std::future<std::string> send(const std::string& data, const std::string& path = "", const std::vector<std::pair<std::string, std::string>>& headers = {}, privmx::utils::CancellationToken::Ptr token = privmx::utils::CancellationToken::create(), const std::string& content_type = "application/octet-stream", bool get = false, bool keepAlive = true) override;
    void disconnect() override;

    // std::function<void(std::string)> notify_callback;

private:
    struct Payload
    {
        Poco::Int32 id;
        std::string data;
        static Payload fromRaw(const std::string& raw_payload);
        static std::string toRaw(const Poco::Int32& id, const std::string& data);
    };

    static const std::chrono::seconds PING_INTERVAL;
    static const std::chrono::seconds PING_TIMEOUT;

    void connect(const std::string& path);
    void processIncomingDataLoop();
    void pingLoop();
    void rejectAllPromises();
    void tryJoinThreads();

    Poco::SharedPtr<Poco::Net::WebSocket> _websocket;
    utils::Mutex _ws_send_mutex;
    Poco::Int32 _id = 1;
    std::map<Poco::Int32, std::promise<std::string>> _promises;
    utils::Mutex _promises_mutex;
    bool _connected = false;
    utils::Mutex _connected_mutex;
    utils::Mutex _state_mutex;
    utils::Mutex _ping_mutex;
    utils::ConditionVariable _ping_cv;
    utils::Mutex _exit_ping_loop_mutex;
    utils::ConditionVariable _exit_ping_loop_cv;
    std::thread _process_incoming_data_thread;
    std::thread _ping_thread;
};

} // pocoimpl
} // rpc
} // privmx

#endif // _PRIVMXLIB_RPC_POCO_WEBSOCKETCHANNEL_HPP_
