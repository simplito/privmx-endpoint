/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/rpc/channel/ChannelEnv.hpp>
#include <privmx/rpc/emscripten/channel/HttpChannel.hpp>
#include <privmx/rpc/emscripten/channel/WebSocketChannel.hpp>

using namespace privmx::rpc;

HttpChannel::Ptr ChannelEnv::getHttpChannel(const Poco::URI& host, const bool keepAlive) {
    return new driverimpl::HttpChannel(host, keepAlive);
}

WebSocketChannel::Ptr ChannelEnv::getWebSocketChannel(const Poco::URI& uri, WebSocketNotify::Ptr notify) {
    return new driverimpl::WebSocketChannel(uri, notify);
}
