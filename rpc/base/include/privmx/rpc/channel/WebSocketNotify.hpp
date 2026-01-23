/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_RPC_WEBSOCKETNOTIFY_HPP_
#define _PRIVMXLIB_RPC_WEBSOCKETNOTIFY_HPP_

#include <functional>
#include <string>
#include <unordered_map>
#include <utility>
#include <condition_variable>
#include <mutex>
#include <queue>
#include <thread>

#include <Poco/JSON/Object.h>
#include <Poco/Types.h>
#include <Poco/SharedPtr.h>

#include <privmx/utils/Types.hpp>
#include <privmx/utils/CancellationToken.hpp>

namespace privmx {
namespace rpc {

struct CallbackWithData {
    std::string data;
    std::function<void(const std::string&)> callback;
};

template <typename T>
class TSQueue {
private:
    std::queue<T> m_queue;
    std::mutex m_mutex;
    std::condition_variable m_cond;

public:
    void push(T item) {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_queue.push(item);
        m_cond.notify_one();
    }

    size_t size() {
        std::unique_lock<std::mutex> lock(m_mutex);
        size_t size = m_queue.size();
        m_cond.notify_one();
        return size;
    }

    T pop() {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_cond.wait(lock,
            [this]() { return !m_queue.empty(); }
        );

        T item = m_queue.front();
        m_queue.pop();
        return item;
    }
};

class WebSocketNotify
{
public:
    using Ptr = Poco::SharedPtr<WebSocketNotify>;
    using CallbackFunc = std::function<void(const std::string&)>;
    using OnWsCloseFunc = std::function<void(void)>;
    ~WebSocketNotify();

    void add(Poco::Int32 wschannelid, CallbackFunc callback, OnWsCloseFunc on_websocket_close);
    void remove(Poco::Int32 wschannelid);
    void notify(const std::string& data);
    void queueForNotify(const std::string data);

    void onWebSocketClose();

    std::function<void(void)> on_close_all_channels;

private:
    using WsChannelFuncs = std::pair<CallbackFunc, OnWsCloseFunc>;
    void notifier();
    void cancelNotifier();
    utils::Mutex _mutex;
    std::unordered_map<Poco::Int32, WsChannelFuncs> _ws_channel_funcs;
    TSQueue<CallbackWithData> _notificationsQueue;
    std::atomic_bool _data_to_notify = false;
    std::atomic_bool _notifier_active = false;
    std::mutex _notifyMutex;
    std::condition_variable _notify_cv;
    std::thread _consumer_thread;
    privmx::utils::CancellationToken::Ptr _notifier_cancellation_token;
};

} // rpc
} // privmx

#endif // _PRIVMXLIB_RPC_WEBSOCKETNOTIFY_HPP_
