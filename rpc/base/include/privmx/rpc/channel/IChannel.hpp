/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_RPC_ICHANNEL_HPP_
#define _PRIVMXLIB_RPC_ICHANNEL_HPP_

#include <future>
#include <Poco/URI.h>
#include <Poco/SharedPtr.h>

#include <privmx/utils/CancellationToken.hpp>

namespace privmx {
namespace rpc {

class IChannel
{
public:
    using Ptr = Poco::SharedPtr<IChannel>;

    IChannel(const Poco::URI& uri) : _uri(uri) {}
    virtual ~IChannel() = default;
    virtual std::future<std::string> send(const std::string& data, const std::string& path = "", const std::vector<std::pair<std::string, std::string>>& headers = {}, privmx::utils::CancellationToken::Ptr token = privmx::utils::CancellationToken::create(), const std::string& content_type = "application/octet-stream", bool get = false, bool keepAlive = true) = 0;

protected:
    Poco::URI _uri;
};

} // rpc
} // privmx

#endif // _PRIVMXLIB_RPC_ICHANNEL_HPP_
