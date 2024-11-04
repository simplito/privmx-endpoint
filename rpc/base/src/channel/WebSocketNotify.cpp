/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <Poco/ByteOrder.h>

#include <privmx/rpc/channel/WebSocketNotify.hpp>
#include <privmx/rpc/RpcException.hpp>

using namespace privmx;
using namespace privmx::rpc;
using namespace privmx::utils;
using namespace std;
using namespace Poco;
using namespace Poco::JSON;

void WebSocketNotify::add(Int32 wschannelid, function<void(const string&)> callback, function<void(void)> on_websocket_close) {
    Lock lock(_mutex);
    _ws_channel_funcs[wschannelid] = make_pair(callback, on_websocket_close);
}

void WebSocketNotify::remove(Int32 wschannelid) {
    {
        Lock lock(_mutex);
        auto it = _ws_channel_funcs.find(wschannelid);
        if (it == _ws_channel_funcs.end()) {
            throw InvalidWsChannelIdException();
        }
        _ws_channel_funcs.erase(it);
    }
    if (_ws_channel_funcs.size() <= 0 && on_close_all_channels) {
        on_close_all_channels();
    }
}

void WebSocketNotify::notify(const string& data) {
    Int32 wschannelid = ByteOrder::fromBigEndian(*((Int32*)data.data()));
    function<void(const string&)> callback;
    {
        Lock lock(_mutex);
        auto it = _ws_channel_funcs.find(wschannelid);
        if(it == _ws_channel_funcs.end()){
            throw InvalidWsChannelIdException();
        }
        callback = (*it).second.first;
    }
    if (callback) {
        callback(data.substr(4));
    }
}

void WebSocketNotify::onWebSocketClose() {
    unordered_map<Int32, WsChannelFuncs> ws_channel_funcs_local;
    {
        Lock lock(_mutex);
        ws_channel_funcs_local = _ws_channel_funcs;
    }
    for (auto &funcs: ws_channel_funcs_local) {
        funcs.second.second();
    }
}
