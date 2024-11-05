/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_RPC_DRIVER_WEBSOCKETCHANNEL_HPP_
#define _PRIVMXLIB_RPC_DRIVER_WEBSOCKETCHANNEL_HPP_

#include <chrono>
#include <future>
#include <functional>
#include <istream>
#include <unordered_map>

#include <privmx/drv/net.h>

#include <privmx/rpc/channel/WebSocketChannel.hpp>
#include <privmx/rpc/channel/WebSocketNotify.hpp>
#include <privmx/utils/Types.hpp>
#include <privmx/utils/CancellationToken.hpp>

namespace privmx {
namespace rpc {
namespace driverimpl {

class WebSocketChannel : public privmx::rpc::WebSocketChannel
{
public:
    using Ptr = Poco::SharedPtr<WebSocketChannel>;

    WebSocketChannel(const Poco::URI& uri, WebSocketNotify::Ptr notify);
    ~WebSocketChannel() override;
    std::future<std::string> send(const std::string& data, const std::string& path = "", const std::vector<std::pair<std::string, std::string>>& headers = {}, privmx::utils::CancellationToken::Ptr token = privmx::utils::CancellationToken::create(), const std::string& content_type = "application/octet-stream", bool get = false, bool keepAlive = true) override;
    void disconnect() override;

private:
    struct Payload
    {
        Poco::Int32 id;
        std::string data;
        static Payload fromRaw(const std::string& raw_payload);
        static std::string toRaw(const Poco::Int32& id, const std::string& data);
    };

    void connect(const std::string& path);
    void rejectAllPromises();
    void tryJoinThreads();
    static void onopen(void* ctx);
    static void onmessage(void* ctx, const char* msg, int msglen);
    static void onerror(void* ctx, const char* msg, int msglen);
    static void onclose(void* ctx, int wasClean);
    void onopen();
    void onmessage(const char* msg, int msglen);
    void onerror(const char* msg, int msglen);
    void onclose(int wasClean);

    privmxDrvNet_Ws* _ws = nullptr;
    Poco::Int32 _id = 1;
    std::map<Poco::Int32, std::promise<std::string>> _promises;
    utils::Mutex _promises_mutex;
    bool _connected = false;
    utils::Mutex _connected_mutex;
    utils::Mutex _state_mutex;
    std::thread _process_incoming_data_thread;
    std::thread _ping_thread;
    std::condition_variable _connected_cv;
};

} // driverimpl
} // rpc
} // privmx

#endif // _PRIVMXLIB_RPC_DRIVER_WEBSOCKETCHANNEL_HPP_
