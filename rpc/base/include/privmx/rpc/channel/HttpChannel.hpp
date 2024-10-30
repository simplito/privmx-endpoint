#ifndef _PRIVMXLIB_RPC_HTTPCHANNEL_HPP_
#define _PRIVMXLIB_RPC_HTTPCHANNEL_HPP_

#include <future>
#include <Poco/SharedPtr.h>

#include <privmx/rpc/channel/IChannel.hpp>
#include <privmx/utils/Types.hpp>
#include <privmx/utils/CancellationToken.hpp>

namespace privmx {
namespace rpc {

class HttpChannel : public IChannel
{
public:
    using Ptr = Poco::SharedPtr<HttpChannel>;

    HttpChannel(const Poco::URI& host) : IChannel(host) {}
    virtual ~HttpChannel() = default;
    virtual std::future<std::string> send(const std::string& data, const std::string& path = "", const std::vector<std::pair<std::string, std::string>>& headers = {}, privmx::utils::CancellationToken::Ptr token = privmx::utils::CancellationToken::create(), const std::string& content_type = "application/octet-stream", bool get = false, bool keepAlive = true) override = 0;

};

} // rpc
} // privmx

#endif // _PRIVMXLIB_RPC_HTTPCHANNEL_HPP_
