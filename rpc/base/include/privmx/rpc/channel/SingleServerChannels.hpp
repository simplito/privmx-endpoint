#ifndef _PRIVMXLIB_RPC_SINGLESERVERCHANNELS_HPP_
#define _PRIVMXLIB_RPC_SINGLESERVERCHANNELS_HPP_

#include <functional>
#include <future>
#include <istream>
#include <vector>
#include <Poco/URI.h>
#include <Poco/SharedPtr.h>

#include <privmx/rpc/channel/HttpChannel.hpp>
#include <privmx/rpc/channel/WebSocketChannel.hpp>
#include <privmx/rpc/channel/WebSocketNotify.hpp>
#include <privmx/utils/Types.hpp>
#include <privmx/utils/CancellationToken.hpp>

namespace privmx {
namespace rpc {

class SingleServerChannels
{
public:
    using Ptr = Poco::SharedPtr<SingleServerChannels>;

    SingleServerChannels(const Poco::URI& uri);
    std::future<std::string> send(const std::string& data, bool web_socket = false, const std::string& path = "", const std::vector<std::pair<std::string, std::string>>& headers = {}, privmx::utils::CancellationToken::Ptr token = privmx::utils::CancellationToken::create(), const std::string& content_type = "application/octet-stream", bool get = false, bool keepAlive = true);
    void setNotifyCallback(const std::function<void(std::string)>& func);
    void destroyWebSocket();

    WebSocketNotify::Ptr notify = new WebSocketNotify();

private:
    struct LockedHttpChannel
    {
        ~LockedHttpChannel(){
            if(free_func) free_func();
        }
        std::function<void()> free_func;
    };

    static const int MAX_HTTP_CLIENTS = 4;

    int getHttpChannel();
    bool tryGetHttpChannel(int& index);
    void free(int index);
    WebSocketChannel::Ptr getWebSocket();

    const Poco::URI _uri;
    std::vector<HttpChannel::Ptr> _http_channels = std::vector<HttpChannel::Ptr>(MAX_HTTP_CLIENTS);
    std::vector<bool> _is_http_free = std::vector<bool>(MAX_HTTP_CLIENTS, true);
    WebSocketChannel::Ptr _websocket;
    utils::Mutex _http_mutex;
    utils::Mutex _websocket_mutex;
    utils::ConditionVariable _http_cv;
    int _http_num_waiting_requests = 0;
    utils::Mutex _websocket_get_mutex;
};

} // rpc
} // privmx

#endif // _PRIVMXLIB_RPC_SINGLESERVERCHANNELS_HPP_
