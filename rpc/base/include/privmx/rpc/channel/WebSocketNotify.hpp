#ifndef _PRIVMXLIB_RPC_WEBSOCKETNOTIFY_HPP_
#define _PRIVMXLIB_RPC_WEBSOCKETNOTIFY_HPP_

#include <functional>
#include <string>
#include <unordered_map>
#include <utility>
#include <Poco/JSON/Object.h>
#include <Poco/Types.h>
#include <Poco/SharedPtr.h>

#include <privmx/utils/Types.hpp>

namespace privmx {
namespace rpc {

class WebSocketNotify
{
public:
    using Ptr = Poco::SharedPtr<WebSocketNotify>;
    using CallbackFunc = std::function<void(const std::string&)>;
    using OnWsCloseFunc = std::function<void(void)>;

    void add(Poco::Int32 wschannelid, CallbackFunc callback, OnWsCloseFunc on_websocket_close);
    void remove(Poco::Int32 wschannelid);
    void notify(const std::string& data);
    void onWebSocketClose();

    std::function<void(void)> on_close_all_channels;

private:
    using WsChannelFuncs = std::pair<CallbackFunc, OnWsCloseFunc>;

    utils::Mutex _mutex;
    std::unordered_map<Poco::Int32, WsChannelFuncs> _ws_channel_funcs;
};

} // rpc
} // privmx

#endif // _PRIVMXLIB_RPC_WEBSOCKETNOTIFY_HPP_
