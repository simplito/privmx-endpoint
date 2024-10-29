#include <privmx/rpc/channel/ChannelEnv.hpp>
#include <privmx/rpc/driver/channel/HttpChannel.hpp>
#include <privmx/rpc/driver/channel/WebSocketChannel.hpp>

using namespace privmx::rpc;

HttpChannel::Ptr ChannelEnv::getHttpChannel(const Poco::URI& host, const bool keepAlive) {
    return new driverimpl::HttpChannel(host, keepAlive);
}

WebSocketChannel::Ptr ChannelEnv::getWebSocketChannel(const Poco::URI& uri, WebSocketNotify::Ptr notify) {
    return new driverimpl::WebSocketChannel(uri, notify);
}
