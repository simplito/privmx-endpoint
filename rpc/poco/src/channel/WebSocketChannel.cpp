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
#include <Poco/Buffer.h>
#include <Poco/ByteOrder.h>
#include <Poco/Net/HTTPRequest.h>
#include <Poco/Net/HTTPResponse.h>
#include <Poco/Net/NetException.h>

#include <privmx/rpc/poco/channel/WebSocketChannel.hpp>
#include <privmx/rpc/poco/utils/HTTPClientSessionFactory.hpp>
#include <privmx/rpc/RpcException.hpp>
#include <privmx/utils/PrivmxException.hpp>
#include <privmx/utils/PrivmxExtExceptions.hpp>
#include <privmx/utils/Utils.hpp>

using namespace privmx;
using namespace privmx::rpc::pocoimpl;
using namespace privmx::utils;
using namespace std;
using namespace Poco;
using namespace Poco::Net;

const chrono::seconds WebSocketChannel::PING_INTERVAL = 10s;
const chrono::seconds WebSocketChannel::PING_TIMEOUT = 3s;

WebSocketChannel::WebSocketChannel(const URI& uri, WebSocketNotify::Ptr notify) : rpc::WebSocketChannel(uri, notify) {
    notify->on_close_all_channels = [&]{ disconnect(); };
}

WebSocketChannel::~WebSocketChannel() {
    disconnect();
}

future<string> WebSocketChannel::send(const string& data, [[maybe_unused]] const string& path, [[maybe_unused]] const std::vector<std::pair<std::string, std::string>>& headers, [[maybe_unused]] privmx::utils::CancellationToken::Ptr token,
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
    Lock lock(_ws_send_mutex);
    _websocket->sendFrame(raw_payload.data(), raw_payload.length(), WebSocket::FRAME_BINARY);
    return future;
}

void WebSocketChannel::disconnect() {
    {
        Lock lock(_connected_mutex);
        if (_connected) {
            Lock lock2(_ws_send_mutex);
            _websocket->shutdown();
        }
    }
    tryJoinThreads();
}

void WebSocketChannel::connect(const std::string& path) {
    Lock lock(_state_mutex);
    Lock lock2(_connected_mutex);
    if (_connected) return;
    tryJoinThreads();
    Poco::SharedPtr<HTTPClientSession> http_client = HTTPClientSessionFactory::create(_uri);
    HTTPRequest request(HTTPRequest::HTTP_GET, path);
    HTTPResponse response;
    try {
        Lock lock(_ws_send_mutex);
        _websocket = new WebSocket(*http_client, request, response);
    } catch (const NetException& e) {
        throw NetConnectionException(e.what());
    } catch (const TimeoutException& e) {
        throw NetConnectionException(e.what());
    }
    _connected = true;
    _process_incoming_data_thread = thread(&WebSocketChannel::processIncomingDataLoop, this);
    _ping_thread = thread(&WebSocketChannel::pingLoop, this);
}

void WebSocketChannel::processIncomingDataLoop() {
    try {
        while (true) {
            Poco::Buffer<char> buf(0);
            int flags;
            int n = _websocket->receiveFrame(buf, flags);
            if (n == 0 && flags == 0) {
                break;
            }
            auto opcode = (flags & WebSocket::FRAME_OP_BITMASK);
            if (opcode == WebSocket::FRAME_OP_PING) {
                Lock lock(_ws_send_mutex);
                _websocket->sendFrame("", 0, WebSocket::FRAME_FLAG_FIN | WebSocket::FRAME_OP_PONG);
                continue;
            }
            if (opcode == WebSocket::FRAME_OP_PONG) {
                _ping_cv.notify_one();
                continue;
            }
            if (n < 4) {
                continue;
            }
            string raw_payload(buf.begin(), buf.begin() + n);
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
                continue;
            }
        }
    } catch (...) {}
    Lock lock(_state_mutex);
    {
        Lock lock(_connected_mutex);
        _connected = false;
    }
    _exit_ping_loop_cv.notify_all();
    _ping_cv.notify_all();
    try {
        _notify->onWebSocketClose();
    } catch (...) {}
    try {
        rejectAllPromises();
    } catch (...) {}
}

void WebSocketChannel::pingLoop() {
    try {
        UniqueLock lock(_exit_ping_loop_mutex);
        while (true) {
            {
                Lock lock(_connected_mutex);
                if (!_connected) return;
            }
            auto wait_status = _exit_ping_loop_cv.wait_for(lock, PING_INTERVAL);
            if (wait_status == cv_status::no_timeout) {
                throw WebSocketPingLoopStoppedException();
            }
            {
                Lock lock(_connected_mutex);
                if (!_connected) return;
            }
            UniqueLock lock2(_ping_mutex);
            {
                Lock lock3(_ws_send_mutex);
                _websocket->sendFrame("", 0, WebSocket::FRAME_FLAG_FIN | WebSocket::FRAME_OP_PING);
            }
            auto status = _ping_cv.wait_for(lock2, PING_TIMEOUT);
            if (status == cv_status::timeout) {
                throw WebSocketPingTimeoutException();
            }
        }
    } catch (...) {
        try {
            Lock lock(_ws_send_mutex);
            _websocket->close();
        } catch (...) {}
    }
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
    if (_ping_thread.joinable()) {
        try {
            _ping_thread.join();
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
