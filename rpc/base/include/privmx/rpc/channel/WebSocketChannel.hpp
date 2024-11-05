/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_RPC_WEBSOCKETCHANNEL_HPP_
#define _PRIVMXLIB_RPC_WEBSOCKETCHANNEL_HPP_

#include <chrono>
#include <future>
#include <functional>
#include <istream>
#include <unordered_map>

#include <privmx/rpc/channel/IChannel.hpp>
#include <privmx/rpc/channel/WebSocketNotify.hpp>
#include <privmx/utils/Types.hpp>
#include <privmx/utils/CancellationToken.hpp>

namespace privmx {
namespace rpc {

class WebSocketChannel : public IChannel
{
public:
    using Ptr = Poco::SharedPtr<WebSocketChannel>;

    WebSocketChannel(const Poco::URI& uri, WebSocketNotify::Ptr notify) : IChannel(uri), _notify(notify) {}
    std::future<std::string> send(const std::string& data, const std::string& path = "",  const std::vector<std::pair<std::string, std::string>>& headers = {}, privmx::utils::CancellationToken::Ptr token = privmx::utils::CancellationToken::create(), const std::string& content_type = "application/octet-stream", bool get = false, bool keepAlive = true) override = 0;
    virtual void disconnect() = 0;
    std::function<void(std::string)> notify_callback;

protected:
    WebSocketNotify::Ptr _notify;
};

} // rpc
} // privmx

#endif // _PRIVMXLIB_RPC_WEBSOCKETCHANNEL_HPP_
