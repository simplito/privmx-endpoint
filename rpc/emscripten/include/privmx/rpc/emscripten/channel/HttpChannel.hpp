#ifndef _PRIVMXLIB_RPC_DRIVER_HTTPCHANNEL_HPP_
#define _PRIVMXLIB_RPC_DRIVER_HTTPCHANNEL_HPP_

#include "net.h"
#include <future>
#include <privmx/rpc/channel/HttpChannel.hpp>
#include <privmx/utils/Types.hpp>
#include <privmx/utils/CancellationToken.hpp>

namespace privmx {
namespace rpc {
namespace driverimpl {

class HttpChannel : public privmx::rpc::HttpChannel
{
public:
    using Ptr = Poco::SharedPtr<HttpChannel>;

    HttpChannel(const Poco::URI& host, bool keepAlive);
    ~HttpChannel();
    std::future<std::string> send(const std::string& data, const std::string& path = "", const std::vector<std::pair<std::string, std::string>>& headers = {}, privmx::utils::CancellationToken::Ptr token = privmx::utils::CancellationToken::create(), const std::string& content_type = "application/octet-stream", bool get = false, bool keepAlive = true) override;

private:
    privmxDrvNet_Http* _http = nullptr;
    utils::Mutex _mutex;
    bool _keepAlive;
};

} // driverimpl
} // rpc
} // privmx

#endif // _PRIVMXLIB_RPC_DRIVER_HTTPCHANNEL_HPP_
