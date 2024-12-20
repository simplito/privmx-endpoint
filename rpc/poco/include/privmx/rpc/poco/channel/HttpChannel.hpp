/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_RPC_POCO_HTTPCHANNEL_HPP_
#define _PRIVMXLIB_RPC_POCO_HTTPCHANNEL_HPP_

#include <future>
#include <Poco/Net/HTTPClientSession.h>
#include <Poco/SharedPtr.h>

#include <privmx/rpc/channel/HttpChannel.hpp>
#include <privmx/utils/Types.hpp>
#include <privmx/utils/CancellationToken.hpp>

namespace privmx {
namespace rpc {
namespace pocoimpl {

class HttpChannel : public privmx::rpc::HttpChannel
{
public:
    using Ptr = Poco::SharedPtr<HttpChannel>;

    HttpChannel(const Poco::URI& host, const bool keepAlive = true);
    std::future<std::string> send(const std::string& data, const std::string& path = "", const std::vector<std::pair<std::string, std::string>>& headers = {}, privmx::utils::CancellationToken::Ptr token = privmx::utils::CancellationToken::create(), const std::string& content_type = "application/octet-stream", bool get = false, bool keepAlive = true) override;

private:
    void updateKeepAlive(const Poco::Net::HTTPResponse& response);
    Poco::SharedPtr<Poco::Net::HTTPClientSession> _http_client;
    utils::Mutex _mutex;
};

} // pocoimpl
} // rpc
} // privmx

#endif // _PRIVMXLIB_RPC_POCO_HTTPCHANNEL_HPP_
