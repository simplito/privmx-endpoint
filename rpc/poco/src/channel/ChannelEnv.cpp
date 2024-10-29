#include <privmx/rpc/channel/ChannelEnv.hpp>
#include <privmx/rpc/poco/channel/HttpChannel.hpp>
#include <privmx/rpc/poco/channel/WebSocketChannel.hpp>

using namespace privmx::rpc;

HttpChannel::Ptr ChannelEnv::getHttpChannel(const Poco::URI& host, const bool keepAlive) {
    return new pocoimpl::HttpChannel(host, keepAlive);
}

WebSocketChannel::Ptr ChannelEnv::getWebSocketChannel(const Poco::URI& uri, WebSocketNotify::Ptr notify) {
    return new pocoimpl::WebSocketChannel(uri, notify);
}
