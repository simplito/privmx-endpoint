// /*
// PrivMX Endpoint.
// Copyright © 2024 Simplito sp. z o.o.
//
// This file is part of the PrivMX Platform (https://privmx.dev).
// This software is Licensed under the PrivMX Free License.
//
// See the License for the specific language governing permissions and
// limitations under the License.
// */
//

#include <Poco/ByteOrder.h>
#include <privmx/rpc/RpcException.hpp>
#include <privmx/utils/Logger.hpp>

using namespace privmx;
using namespace privmx::rpc;
using namespace privmx::utils;
using namespace std;
using namespace Poco;
using namespace Poco::JSON;

WebSocketNotify::~WebSocketNotify() {
    cancelNotifier();
}

// -----------------------------------
// add / remove
// -----------------------------------

void WebSocketNotify::add(Int32 wschannelid,
                          function<void(const string&)> callback,
                          function<void(void)> on_websocket_close)
{
    LOG_DEBUG("WebsocketNotify::add(wschannelid): ", wschannelid);
    Lock lock(_mutex);
    _ws_channel_funcs[wschannelid] = make_pair(callback, on_websocket_close);
}

void WebSocketNotify::remove(Int32 wschannelid) {
    LOG_TRACE("WebSocketNotify::remove wschannelid: ", wschannelid);
    {
        LOG_DEBUG("webSocketNotify 1");
        Lock lock(_mutex);
        LOG_DEBUG("webSocketNotify 2");
        auto it = _ws_channel_funcs.find(wschannelid);
        if (it == _ws_channel_funcs.end()) {
            LOG_DEBUG("webSocketNotify: InvalidWsChannelIdException");
            throw InvalidWsChannelIdException();
        }
        LOG_DEBUG("webSocketNotify 3");
        _ws_channel_funcs.erase(it);
        shouldCloseAll = _ws_channel_funcs.empty();
    }

    if (shouldCloseAll && on_close_all_channels) {
        LOG_DEBUG("webSocketNotify 4");
        on_close_all_channels();
    }
    if (_notifier_active) {
        cancelNotifier();
    }
}

// -----------------------------------
// notify
// -----------------------------------

void WebSocketNotify::notify(const string& data) {
    Int32 wschannelid = ByteOrder::fromBigEndian(*((Int32*)data.data()));
    function<void(const string&)> callback;
    {
        Lock lock(_mutex);
        auto it = _ws_channel_funcs.find(wschannelid);
        if (it == _ws_channel_funcs.end()) {
            throw InvalidWsChannelIdException();
        }
        callback = it->second.first;
    }
    if (callback) {
        callback(data.substr(4));
    }
}

// -----------------------------------
// queueForNotify
// -----------------------------------

void WebSocketNotify::queueForNotify(const string data) {
    // Uruchom wątek konsumenta tylko raz (atomicznie).
    bool was_active = _notifier_active.exchange(true, std::memory_order_acq_rel);
    if (!was_active) {
        LOG_DEBUG("queueForNotify: starting consumer thread");
        _notifier_cancellation_token = privmx::utils::CancellationToken::create();
        _consumer_thread = std::thread([&](privmx::utils::CancellationToken::Ptr token){
            while(!token->isCancelled()) {
                notifier();
            }
            LOG_TRACE("WebSocketNotify::ConsumerThread exited");
        }, _notifier_cancellation_token);
    }

    Int32 wschannelid = ByteOrder::fromBigEndian(*((Int32*)data.data()));
    function<void(const string&)> callback;
    {
        Lock lock(_mutex);
        auto it = _ws_channel_funcs.find(wschannelid);
        if (it == _ws_channel_funcs.end()) {
            throw InvalidWsChannelIdException();
        }
        callback = it->second.first;
    }
    if (callback) {
        CallbackWithData pair{
            .data = data,
            .callback = callback
        };
        _notificationsQueue.push(pair);

        {
            lock_guard<std::mutex> lock(_notifyMutex);
            _data_to_notify.store(true, std::memory_order_release);
        }
        _notify_cv.notify_one();
    }
}

// -----------------------------------
// onWebSocketClose
// -----------------------------------

void WebSocketNotify::onWebSocketClose() {
    cancelNotifier();

    unordered_map<Int32, WsChannelFuncs> ws_channel_funcs_local;
    {
        Lock lock(_mutex);
        ws_channel_funcs_local = _ws_channel_funcs;
    }
    for (auto &funcs : ws_channel_funcs_local) {
        funcs.second.second();
    }
}

void WebSocketNotify::notifier() {
    unique_lock<std::mutex>lock(_notifyMutex);
    _notify_cv.wait(lock, [&] {
        return _data_to_notify.load() || _notifier_cancellation_token->isCancelled();
    });
    if(_notifier_cancellation_token->isCancelled()) {
        LOG_TRACE("WebSocketNotify::notifier Canceled");
        return;
    } 

    while(_notificationsQueue.size() > 0) {
        auto ret {_notificationsQueue.pop()};
        ret.callback(ret.data.substr(4));
    };
    _data_to_notify.store(false);
}

// -----------------------------------
// cancelNotifier
// -----------------------------------

void WebSocketNotify::cancelNotifier() {
    LOG_TRACE("WebSocketNotify::cancelNotifier")
    if(!_notifier_cancellation_token.isNull()) {
        _notifier_cancellation_token->cancel();
    }
    _data_to_notify.store(true);
    _notify_cv.notify_all();
    if (_consumer_thread.joinable()) {
        _consumer_thread.join();
    }
    _notifier_active = false;
    LOG_TRACE("WebSocketNotify::cancelNotifier cancelled");
}
