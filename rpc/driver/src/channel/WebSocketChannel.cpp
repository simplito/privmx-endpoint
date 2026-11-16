/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <sstream>
#include <thread>
#include <Poco/ByteOrder.h>

#include <privmx/drv/net.h>
#include <privmx/rpc/driver/channel/WebSocketChannel.hpp>
#include <privmx/utils/PrivmxException.hpp>
#include <privmx/utils/PrivmxExtExceptions.hpp>
#include <privmx/utils/Utils.hpp>
#include <privmx/rpc/RpcException.hpp>

#include <privmx/crypto/OpenSSLUtils.hpp>

using namespace privmx;
using namespace privmx::rpc::driverimpl;
using namespace privmx::utils;
using namespace std;
using namespace Poco;

WebSocketChannel::WebSocketChannel(const URI& uri, WebSocketNotify::Ptr notify) : rpc::WebSocketChannel(uri, notify) {
    notify->on_close_all_channels = [this]{ disconnect(); };
}

WebSocketChannel::~WebSocketChannel() {
    disconnect();
}

future<string> WebSocketChannel::send(const string& data, const string& path, [[maybe_unused]] const std::vector<std::pair<std::string, std::string>>& headers, [[maybe_unused]] privmx::utils::CancellationToken::Ptr token,
        [[maybe_unused]] const string& content_type, [[maybe_unused]] bool get, [[maybe_unused]] bool keepAlive) {
    connect(path);
    {
        UniqueLock lock(_connected_mutex);
        _connected_cv.wait(lock, [this] { return _socket_state != SocketState::Connecting || _disconnecting; });
    }
    // Held from here on so that a disconnect racing this send waits at its callback barrier
    // instead of freeing _ws underneath privmxDrvNet_wsSend.
    RecursiveLock callback_lock(_callback_mutex);
    privmxDrvNet_Ws* ws = nullptr;
    {
        Lock lock(_connected_mutex);
        if (_socket_state == SocketState::Open) {
            ws = _ws;
        }
    }
    if (ws == nullptr) {
        throw WebsocketDisconnectedException();
    }
    std::future<string> future;
    Int32 id;
    {
        Lock lock(_promises_mutex);
        id = _id++;
        _promises.emplace(make_pair(id, promise<string>()));
        future = _promises[id].get_future();
    }
    string raw_payload = Payload::toRaw(id, data);
    int status = privmxDrvNet_wsSend(ws, raw_payload.data(), raw_payload.length());
    if (status != 0) {
        Lock lock(_promises_mutex);
        _promises.erase(id);
        throw WsSend1Exception("wsSend1: " + to_string(status));
    }
    return future;
}

void WebSocketChannel::disconnect() {
    _disconnecting = true;
    privmxDrvNet_Ws* ws = nullptr;
    bool was_open = false;
    {
        Lock lock(_connected_mutex);
        ws = _ws;
        was_open = _socket_state == SocketState::Open;
        _ws = nullptr;
        _socket_state = SocketState::Closed;
    }
    // Wakes senders parked in send(); with _ws gone they fail instead of waiting for an open that
    // the driver will no longer report.
    _connected_cv.notify_all();
    // Closing the socket makes the driver fire onclose on its own thread; wait for callbacks and
    // sends already inside to return before the socket is freed and this channel is destroyed.
    { RecursiveLock callback_lock(_callback_mutex); }
    if (ws != nullptr) {
        if (was_open) {
            privmxDrvNet_wsClose(ws);
        }
        privmxDrvNet_wsFree(ws);
    }
    // onclose is suppressed for this close, so the senders it would have failed are failed here.
    try { rejectAllPromises(); } catch (...) {}
    tryJoinThreads();
}

void WebSocketChannel::connect(const std::string& path) {
    Lock lock(_state_mutex);
    {
        Lock connected_lock(_connected_mutex);
        if (_socket_state == SocketState::Open || _socket_state == SocketState::Connecting) return;
        _socket_state = SocketState::Connecting;
        _disconnecting = false;
    }
    tryJoinThreads();
    Poco::URI url2 = _uri;
    url2.setPath(path);
    string url = url2.toString();
    privmxDrvNet_Ws* ws;
    privmxDrvNet_WsOptions options;
    options.url = url.c_str();
    int status = privmxDrvNet_wsConnect(&options, &WebSocketChannel::onopen, &WebSocketChannel::onmessage, &WebSocketChannel::onerror, &WebSocketChannel::onclose, this, &ws);
    if (status != 0) {
        {
            Lock connected_lock(_connected_mutex);
            _socket_state = SocketState::Closed;
        }
        _connected_cv.notify_all();
        throw WsConnectException(to_string(status));
    }
    {
        Lock connected_lock(_connected_mutex);
        _ws = ws;
    }
    // onopen may already have run on the driver thread, so senders waiting for _ws are woken here.
    _connected_cv.notify_all();
}

void WebSocketChannel::rejectAllPromises() {
    Lock lock(_promises_mutex);
    for (auto& promise : _promises) {
        promise.second.set_exception(make_exception_ptr(
            WebsocketDisconnectedException()));
    }
    _promises.clear();
}

void WebSocketChannel::tryJoinThreads() {
    if (_process_incoming_data_thread.joinable()) {
        try {
            _process_incoming_data_thread.join();
        } catch (...) {}
    }
}

WebSocketChannel::Payload WebSocketChannel::Payload::fromRaw(const string& raw_payload) {
    if (raw_payload.length() < 4) {
        throw WebSocketInvalidPayloadLengthException();
    }
    string id_buf(raw_payload.begin(), raw_payload.begin() + 4);
    Payload result;
    result.id = ByteOrder::fromBigEndian(*((Int32*)id_buf.data()));
    result.data = string(raw_payload.begin() + 4, raw_payload.end());
    return result;
}

string WebSocketChannel::Payload::toRaw(const Int32& id, const string& data) {
    Int32 id_be = ByteOrder::toBigEndian(id);
    return string((char*)&id_be, 4) + data;
}


// Shuts the driver out once teardown has begun and keeps this channel alive for the duration of a
// callback that got in before that, which is what disconnect() waits for at its barrier.
void WebSocketChannel::runCallback(void* ctx, const std::function<void(WebSocketChannel&)>& callback) {
    WebSocketChannel* channel = static_cast<WebSocketChannel*>(ctx);
    RecursiveLock lock(channel->_callback_mutex);
    if (channel->_disconnecting) {
        return;
    }
    callback(*channel);
}

void WebSocketChannel::onopen(void* ctx) {
    runCallback(ctx, [](WebSocketChannel& channel) { channel.onopen(); });
}

void WebSocketChannel::onmessage(void* ctx, const char* msg, int msglen) {
    runCallback(ctx, [&](WebSocketChannel& channel) { channel.onmessage(msg, msglen); });
}

void WebSocketChannel::onerror(void* ctx, const char* msg, int msglen) {
    runCallback(ctx, [&](WebSocketChannel& channel) { channel.onerror(msg, msglen); });
}

void WebSocketChannel::onclose(void* ctx, int wasClean) {
    runCallback(ctx, [&](WebSocketChannel& channel) { channel.onclose(wasClean); });
}

void WebSocketChannel::onopen() {
    {
        Lock lock(_connected_mutex);
        _socket_state = SocketState::Open;
    }
    _connected_cv.notify_all();
}

void WebSocketChannel::onmessage(const char* msg, int msglen) {
    try {
        string raw_payload(msg, msglen);     
        Payload payload = Payload::fromRaw(raw_payload);
        if (payload.id == 0) {
            try {
                _notify->queueForNotify(payload.data);
            } catch (...) {}
        } else {
            Lock lock(_promises_mutex);
            auto promise = _promises.find(payload.id);
            if(promise == _promises.end()){
                throw InvalidWebSocketRequestIdException();
            }
            (*promise).second.set_value(payload.data);
            _promises.erase(promise);
        }
    } catch (...) {}
}

void WebSocketChannel::onerror([[maybe_unused]] const char* msg, [[maybe_unused]] int msglen) {
    try {
        rejectAllPromises();
    } catch (...) {}
}

void WebSocketChannel::onclose([[maybe_unused]] int wasClean) {
    Lock lock(_state_mutex);
    {
        Lock connected_lock(_connected_mutex);
        _socket_state = SocketState::Closed;
    }
    // A sender waiting for this socket to open will never get it, so wake it to fail instead.
    _connected_cv.notify_all();
    try {
        _notify->onWebSocketClose();
    } catch (...) {}
    try {
        rejectAllPromises();
    } catch (...) {}
}
