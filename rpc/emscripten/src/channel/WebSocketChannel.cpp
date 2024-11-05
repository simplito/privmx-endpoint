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
#include <privmx/rpc/emscripten/channel/WebSocketChannel.hpp>
#include <privmx/utils/PrivmxException.hpp>
#include <privmx/utils/PrivmxExtExceptions.hpp>
#include <privmx/utils/Utils.hpp>
#include <privmx/rpc/RpcException.hpp>
#include <emscripten/emscripten.h>
#include <emscripten/bind.h>
#include <privmx/crypto/OpenSSLUtils.hpp>

using namespace privmx;
using namespace privmx::rpc::driverimpl;
using namespace privmx::utils;
using namespace std;
using namespace Poco;

WebSocketChannel::WebSocketChannel(const URI& uri, WebSocketNotify::Ptr notify) : rpc::WebSocketChannel(uri, notify) {
    notify->on_close_all_channels = [&]{ disconnect(); };
}

WebSocketChannel::~WebSocketChannel() {
    disconnect();
}

future<string> WebSocketChannel::send(const string& data, const string& path, [[maybe_unused]] const std::vector<std::pair<std::string, std::string>>& headers, [[maybe_unused]] privmx::utils::CancellationToken::Ptr token,
        [[maybe_unused]] const string& content_type, [[maybe_unused]] bool get, [[maybe_unused]] bool keepAlive) {
    connect(path);
    std::future<string> future;
    Int32 id;
    {
        Lock lock(_promises_mutex);
        id = _id++;
        _promises.emplace(make_pair(id, promise<string>()));
        future = _promises[id].get_future();
    }
    string raw_payload = Payload::toRaw(id, data);
    if(!_connected){
        do{
            emscripten_sleep(10);
        } while (!_connected);
    }
    int status = privmxDrvNet_wsSend(_ws, raw_payload.data(), raw_payload.length());
    if (status != 0) {
        throw WsSend1Exception("wsSend1: " + to_string(status));
    }
    return future;
}

void WebSocketChannel::disconnect() {
    {
        Lock lock(_connected_mutex);
        if (_ws != nullptr) {
            if (_connected) {
                privmxDrvNet_wsClose(_ws);
                _connected = false;
            }
            privmxDrvNet_wsFree(_ws);
            _ws = nullptr;
        }
    }
    tryJoinThreads();
}

void WebSocketChannel::connect(const std::string& path) {
    Lock lock(_state_mutex);
    Lock lock2(_connected_mutex);
    if (_connected) return;
    tryJoinThreads();
    Poco::URI url2 = _uri;
    url2.setPath(path);
    string url = url2.toString();
    privmxDrvNet_Ws* ws;
    privmxDrvNet_WsOptions options;
    options.url = url.c_str();
    int status = privmxDrvNet_wsConnect(&options, &WebSocketChannel::onopen, &WebSocketChannel::onmessage, &WebSocketChannel::onerror, &WebSocketChannel::onclose, this, &ws);
    if (status != 0) {
        throw WsConnectException(to_string(status));
    }
    _ws = ws;
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


void WebSocketChannel::onopen(void* ctx) {
    WebSocketChannel* channel = static_cast<WebSocketChannel*>(ctx);
    channel->onopen();
}

void WebSocketChannel::onmessage(void* ctx, const char* msg, int msglen) {
    WebSocketChannel* channel = static_cast<WebSocketChannel*>(ctx);
    channel->onmessage(msg, msglen);
}

void WebSocketChannel::onerror(void* ctx, const char* msg, int msglen) {
    WebSocketChannel* channel = static_cast<WebSocketChannel*>(ctx);
    channel->onerror(msg, msglen);
}

void WebSocketChannel::onclose(void* ctx, int wasClean) {
    WebSocketChannel* channel = static_cast<WebSocketChannel*>(ctx);
    channel->onclose(wasClean);
}

void WebSocketChannel::onopen() {
    _connected = true;
    _connected_cv.notify_all();
}

void WebSocketChannel::onmessage(const char* msg, int msglen) {
    try {
        string raw_payload(msg, msglen);
        Payload payload = Payload::fromRaw(raw_payload);
        if (payload.id == 0) {
            try {
                _notify->notify(payload.data);
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
        Lock lock(_connected_mutex);
        _connected = false;
    }
    try {
        _notify->onWebSocketClose();
    } catch (...) {}
    try {
        rejectAllPromises();
    } catch (...) {}
}
