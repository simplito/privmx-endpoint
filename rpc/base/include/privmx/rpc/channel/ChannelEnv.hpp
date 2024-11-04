/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

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
