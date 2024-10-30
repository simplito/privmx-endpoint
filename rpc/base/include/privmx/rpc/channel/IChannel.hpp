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
