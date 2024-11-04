/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/rpc/channel/ChannelManager.hpp>

using namespace privmx;
using namespace privmx::rpc;
using namespace privmx::utils;
using namespace std;
using namespace Poco;

ChannelManager::Ptr ChannelManager::_instance = new ChannelManager();

ChannelManager::Ptr ChannelManager::getInstance() {
    return _instance;
}

SingleServerChannels::Ptr ChannelManager::add(const URI& uri) {
    string host = uri.getScheme() + uri.getHost() + ":" + std::to_string(uri.getPort());
    Lock lock(_servers_mutex);
    auto it = _servers.find(host);
    if (it == _servers.end()) {
        SingleServer new_server{new SingleServerChannels(uri), 1};
        _servers.emplace(host, new_server);
        return new_server.server;
    }
    (*it).second.count++;
    return (*it).second.server;
}

void ChannelManager::remove(const URI& uri) {
    string host = uri.getScheme() + uri.getHost() + ":" + std::to_string(uri.getPort());
    Lock lock(_servers_mutex);
    auto it = _servers.find(host);
    if (it == _servers.end()) return;
    (*it).second.count--;
    if ((*it).second.count <= 0) {
        _servers.erase(it);
    }
}
