/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/rpc/channel/SingleServerChannels.hpp>
#include <privmx/rpc/RpcException.hpp>
#include <privmx/rpc/channel/ChannelEnv.hpp>

using namespace privmx;
using namespace privmx::rpc;
using namespace privmx::utils;
using namespace std;
using namespace Poco;

SingleServerChannels::SingleServerChannels(const URI& uri) : _uri(uri) {}

future<string> SingleServerChannels::send(const string& data, bool web_socket, const string& path, const std::vector<std::pair<std::string, std::string>>& headers, privmx::utils::CancellationToken::Ptr token, const string& content_type, bool get, bool keepAlive) {
    if (web_socket) {
        return getWebSocket()->send(data, path);
    }
    int index = getHttpChannel();
    LockedHttpChannel locked_channel{[&, index]{ free(index); }};
    token->validate();
    auto result = _http_channels[index]->send(data, path, headers, token, content_type, get, keepAlive);

    token->validate();
    return result;
}

int SingleServerChannels::getHttpChannel(){
    UniqueLock lock(_http_mutex);
    int index;
    if (!_http_num_waiting_requests && tryGetHttpChannel(index)) {
        return index;
    }
    ++_http_num_waiting_requests;
    _http_cv.wait(lock);
    --_http_num_waiting_requests;
    if (tryGetHttpChannel(index)) {
        return index;
    }
    throw ErrorDuringGettingHTTPChannelException();
}

bool SingleServerChannels::tryGetHttpChannel(int& index) {
    for (int i = 0; i < (int)_http_channels.size(); ++i) {
        if (_is_http_free[i] == true) {
            if (_http_channels[i].isNull()) {
                _http_channels[i] = ChannelEnv::getHttpChannel(_uri);
            }
            _is_http_free[i] = false;
            index = i;
            return true;
        }
    }
    return false;
}

void SingleServerChannels::free(int index) {
    Lock lock(_http_mutex);
    _is_http_free[index] = true;
    _http_cv.notify_one();
}

WebSocketChannel::Ptr SingleServerChannels::getWebSocket() {
    Lock lock(_websocket_get_mutex);
    if (_websocket.isNull()) {
        _websocket = ChannelEnv::getWebSocketChannel(_uri, notify);
    }
    return _websocket;
}

void SingleServerChannels::setNotifyCallback(const function<void(string)>& func) {
    getWebSocket()->notify_callback = func;
}

void SingleServerChannels::destroyWebSocket() {
    auto web_socket = getWebSocket();
    web_socket->disconnect();
}