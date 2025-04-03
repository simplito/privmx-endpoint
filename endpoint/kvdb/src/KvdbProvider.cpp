/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/kvdb/KvdbProvider.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::kvdb;

KvdbProvider::KvdbProvider(std::function<server::KvdbInfo(std::string)> getKvdb) : core::ContainerProvider<std::string, server::KvdbInfo>(getKvdb) {}
    
void KvdbProvider::updateByValue(const server::KvdbInfo& container) {
    auto cached = _storage.get(container.id());
    if(!cached.has_value()) {
        _storage.set(container.id(), container);
        return;
    }
    auto cached_container = cached.value();
    if(container.version() > cached_container.version() || container.lastModificationDate() > cached_container.lastModificationDate()) {
        _storage.set(container.id(), container);
    }
}

void KvdbProvider::updateStats(const server::KvdbStatsEventData& stats) {
    auto kvdbInfo = this->get(stats.kvdbId());
    updateByValue(kvdbInfo);
}