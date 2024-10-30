#ifndef _PRIVMXLIB_RPC_CHANNELENV_HPP_
#define _PRIVMXLIB_RPC_CHANNELENV_HPP_

#include <future>
#include <Poco/SharedPtr.h>

#include <privmx/rpc/channel/HttpChannel.hpp>
#include <privmx/rpc/channel/WebSocketChannel.hpp>

namespace privmx {
namespace rpc {

class ChannelEnv
{
public:
    static HttpChannel::Ptr getHttpChannel(const Poco::URI& host, const bool keepAlive = true);
    static WebSocketChannel::Ptr getWebSocketChannel(const Poco::URI& uri, WebSocketNotify::Ptr notify);
};

} // rpc
} // privmx

#endif // _PRIVMXLIB_RPC_CHANNELENV_HPP_
