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
// #include <Poco/ByteOrder.h>
//
// #include <privmx/rpc/RpcException.hpp>
// #include <privmx/rpc/channel/WebSocketNotify.hpp>
//
// #include "privmx/utils/Logger.hpp"
//
// using namespace privmx;
// using namespace privmx::rpc;
// using namespace privmx::utils;
// using namespace std;
// using namespace Poco;
// using namespace Poco::JSON;
//
// WebSocketNotify::~WebSocketNotify() {
//     cancelNotifier();
// }
//
//
// void WebSocketNotify::add(Int32 wschannelid, function<void(const string&)> callback, function<void(void)> on_websocket_close) {
//     Lock lock(_mutex);
//     _ws_channel_funcs[wschannelid] = make_pair(callback, on_websocket_close);
// }
//
// void WebSocketNotify::remove(Int32 wschannelid) {
//     bool shouldCloseAll = false;
//     {
//         LOG_DEBUG("webSocketNotify 1")
//         Lock lock(_mutex);
//         LOG_DEBUG("webSocketNotify 2")
//         auto it = _ws_channel_funcs.find(wschannelid);
//         if (it == _ws_channel_funcs.end()) {
//             LOG_DEBUG("webSocketNotify: InvalidWsChannelIdException")
//             throw InvalidWsChannelIdException();
//         }
//         LOG_DEBUG("webSocketNotify 3")
//         _ws_channel_funcs.erase(it);
//         shouldCloseAll = _ws_channel_funcs.empty();
//     }
//     if (shouldCloseAll && on_close_all_channels) {
//         LOG_DEBUG("webSocketNotify 4")
//         on_close_all_channels();
//     }
//     if (_notifier_active) {
//         LOG_DEBUG("webSocketNotify 5")
//         if(!_notifier_cancellation_token.isNull()) {
//             LOG_DEBUG("webSocketNotify 6")
//             _notifier_cancellation_token->cancel();
//         }
//         LOG_DEBUG("webSocketNotify 7")
//         _notify_cv.notify_one();
//         // if (_consumer_thread.joinable()) {
//         LOG_DEBUG("webSocketNotify 8")
//             // _consumer_thread.join();
//             cancelNotifier();
//
//         // }
//         _notifier_active = false;
//         LOG_DEBUG("webSocketNotify 9")
//     }
// }
//
// void WebSocketNotify::notify(const string& data) {
//     Int32 wschannelid = ByteOrder::fromBigEndian(*((Int32*)data.data()));
//     function<void(const string&)> callback;
//     {
//         Lock lock(_mutex);
//         auto it = _ws_channel_funcs.find(wschannelid);
//         if(it == _ws_channel_funcs.end()){
//             throw InvalidWsChannelIdException();
//         }
//         callback = (*it).second.first;
//     }
//     if (callback) {
//         callback(data.substr(4));
//     }
// }
//
// void WebSocketNotify::queueForNotify(const string data) {
//     bool expected = false;
//     if (_notifier_active.compare_exchange_strong(expected, true)) {
//         _notifier_cancellation_token = privmx::utils::CancellationToken::create();
//         _consumer_thread = std::thread([&](privmx::utils::CancellationToken::Ptr token){
//             while(!token->isCancelled()) {
//                 LOG_DEBUG("queueForNotify: notifier()")
//                 notifier();
//                 LOG_DEBUG("queueForNotify: after notifier()")
//             }
//             LOG_DEBUG("queueForNotify: after while")
//         }, _notifier_cancellation_token);
//     }
//
//     Int32 wschannelid = ByteOrder::fromBigEndian(*((Int32*)data.data()));
//     function<void(const string&)> callback;
//     {
//         Lock lock(_mutex);
//         auto it = _ws_channel_funcs.find(wschannelid);
//         if(it == _ws_channel_funcs.end()){
//             throw InvalidWsChannelIdException();
//         }
//         callback = (*it).second.first;
//     }
//     if (callback) {
//         CallbackWithData pair = {
//             .data = data,
//             .callback = callback
//         };
//         _notificationsQueue.push(pair);
//
//         lock_guard<std::mutex>lock(_notifyMutex);
//         _data_to_notify = true;
//         _notify_cv.notify_one();
//     }
// }
//
// void WebSocketNotify::onWebSocketClose() {
//     cancelNotifier();
//     unordered_map<Int32, WsChannelFuncs> ws_channel_funcs_local;
//     {
//         Lock lock(_mutex);
//         ws_channel_funcs_local = _ws_channel_funcs;
//     }
//     for (auto &funcs: ws_channel_funcs_local) {
//         funcs.second.second();
//     }
// }
//
// void WebSocketNotify::notifier() {
//     // unique_lock<std::mutex>lock(_notifyMutex);
//     // _notify_cv.wait(lock, [&] {
//     //     return _data_to_notify.load();
//     // });
//     // while(_notificationsQueue.size() > 0) {
//     //     auto ret {_notificationsQueue.pop()};
//     //     ret.callback(ret.data.substr(4));
//     // };
//     //
//     // _data_to_notify.store(false);
//     LOG_DEBUG("notifier 1");
//     unique_lock<std::mutex>lock(_notifyMutex);
//     _notify_cv.wait(lock, [&] {
//         return _data_to_notify.load();
//     });
//     LOG_DEBUG("notifier 2");
//
//     if(_notifier_cancellation_token->isCancelled()) {
//         LOG_DEBUG("notifier 3");
//         _data_to_notify.store(false);
//         return;
//     }
//     LOG_DEBUG("notifier 4");
//
//     while(_notificationsQueue.size() > 0) {
//         auto ret {_notificationsQueue.pop()};
//         ret.callback(ret.data.substr(4));
//     };
//     LOG_DEBUG("notifier 5");
//
//
//     _data_to_notify.store(false);
//     LOG_DEBUG("notifier 6");
//
// }
//
// void WebSocketNotify::cancelNotifier() {
//     LOG_DEBUG("cancelNotifier 1");
//     if(!_notifier_cancellation_token.isNull()) {
//         _notifier_cancellation_token->cancel();
//     }
//     _data_to_notify.store(true);
//     LOG_DEBUG("cancelNotifier 4");
//     _notify_cv.notify_one();
//     LOG_DEBUG("cancelNotifier 5");
//
//     if (_consumer_thread.joinable() &&
//         _consumer_thread.get_id() != std::this_thread::get_id()) {
//         LOG_DEBUG("cancelNotifier 6");
//
//         _consumer_thread.join();
//     }
//     LOG_DEBUG("cancelNotifier 7");
//
// }
/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.
This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.
See the License for the specific language governing permissions and
limitations under the License.
*/
#include <Poco/ByteOrder.h>
#include <privmx/rpc/RpcException.hpp>
#include <privmx/rpc/channel/WebSocketNotify.hpp>
#include "privmx/utils/Logger.hpp"

#include <atomic>
#include <thread>
#include <mutex>
#include <unordered_map>

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
    bool shouldCloseAll = false;

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

    // Od tego momentu nie ma już kanałów; jeśli wątek notyfikacji działa, zatrzymaj go.
    // Zawsze używamy cancelNotifier() – ono samo zadba, czy joinować, czy nie.
    if (_notifier_active.load(std::memory_order_acquire)) {
        LOG_DEBUG("webSocketNotify 5");
        cancelNotifier();
        LOG_DEBUG("webSocketNotify 9");
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

        _consumer_thread = std::thread(
            [this](privmx::utils::CancellationToken::Ptr token) {
                LOG_DEBUG("consumer_thread: started, id = ", std::this_thread::get_id());

                while (!token->isCancelled()) {
                    LOG_DEBUG("consumer_thread: before notifier(), cancelled=", token->isCancelled());
                    notifier();
                    LOG_DEBUG("consumer_thread: after notifier(), cancelled=", token->isCancelled());
                }

                LOG_DEBUG("consumer_thread: exiting loop, cancelled=", token->isCancelled());
            },
            _notifier_cancellation_token
        );
        LOG_DEBUG("queueForNotify: consumer thread created, joinable=",  _consumer_thread.joinable());
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

// -----------------------------------
// notifier (wątek konsumenta)
// -----------------------------------

void WebSocketNotify::notifier() {
    LOG_DEBUG("notifier: enter");
    unique_lock<std::mutex> lock(_notifyMutex);

    LOG_DEBUG("notifier: before wait, data_to_notify="
              , _data_to_notify.load(std::memory_order_acquire)
              , " cancelled=" , (!_notifier_cancellation_token.isNull() && _notifier_cancellation_token->isCancelled()));

    _notify_cv.wait(lock, [&] {
        auto data_flag = _data_to_notify.load(std::memory_order_acquire);
        auto cancelled = (!_notifier_cancellation_token.isNull()
                          && _notifier_cancellation_token->isCancelled());
        LOG_DEBUG("notifier: wake predicate check, data_to_notify="
                  ,data_flag , " cancelled=", cancelled);
        return data_flag || cancelled;
    });

    LOG_DEBUG("notifier: after wait, data_to_notify="
              , _data_to_notify.load(std::memory_order_acquire)
              , " cancelled=" , (!_notifier_cancellation_token.isNull() && _notifier_cancellation_token->isCancelled()));

    if (!_notifier_cancellation_token.isNull()
        && _notifier_cancellation_token->isCancelled()) {
        LOG_DEBUG("notifier: cancellation branch, clearing queue");
        while (_notificationsQueue.size() > 0) {
            _notificationsQueue.pop();
        }
        _data_to_notify.store(false, std::memory_order_release);
        LOG_DEBUG("notifier: leaving (cancel)");
        return;
        }

    LOG_DEBUG("notifier: processing queue");
    while (_notificationsQueue.size() > 0) {
        auto ret{_notificationsQueue.pop()};
        LOG_DEBUG("notifier: invoking callback");
        ret.callback(ret.data.substr(4));
        LOG_DEBUG("notifier: callback returned");
    }

    _data_to_notify.store(false, std::memory_order_release);
    LOG_DEBUG("notifier: leaving (normal)");
}

// -----------------------------------
// cancelNotifier
// -----------------------------------

void WebSocketNotify::cancelNotifier() {
    LOG_DEBUG("cancelNotifier 1 (thread id=", std::this_thread::get_id(), ")");

    bool was_active = _notifier_active.exchange(false, std::memory_order_acq_rel);
    LOG_DEBUG("cancelNotifier 2 was_active=", was_active);

    if (!was_active) {
        LOG_DEBUG("cancelNotifier 3: not active, skipping");
        return;
    }

    if (!_notifier_cancellation_token.isNull()) {
        LOG_DEBUG("cancelNotifier 4: cancelling token");
        _notifier_cancellation_token->cancel();
    }

    {
        lock_guard<std::mutex> lock(_notifyMutex);
        _data_to_notify.store(true, std::memory_order_release);
    }

    LOG_DEBUG("cancelNotifier 5: notifying cv");
    _notify_cv.notify_one();

    // #if !defined(__EMSCRIPTEN__)
        if (_consumer_thread.joinable() && _consumer_thread.get_id() != std::this_thread::get_id()) {
            LOG_DEBUG("cancelNotifier 6: joinable, joining");
            _consumer_thread.join();
            LOG_DEBUG("cancelNotifier 7: joined");
        } else {
                LOG_DEBUG("cancelNotifier 6: not joinable or same thread, skipping join");
        }
    // #else

        // LOG_DEBUG("cancelNotifier 6: WASM build – skipping join()");
    // #endif

    LOG_DEBUG("cancelNotifier: end");
}