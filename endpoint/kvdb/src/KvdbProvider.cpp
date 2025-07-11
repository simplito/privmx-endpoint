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

KvdbProvider::KvdbProvider(std::function<server::KvdbInfo(std::string)> getKvdb, std::function<uint32_t(server::KvdbInfo)> validateKvdb) 
    : core::ContainerProvider<std::string, server::KvdbInfo>(getKvdb, validateKvdb) {}
    
bool KvdbProvider::isNewerOrSameAsInStorage(const server::KvdbInfo& container) {
    auto cached = _storage.get(container.id());
    if(!cached.has_value()) {
        return true;
    }
    auto cached_container = cached.value().container;
    if(container.version() > cached_container.version() || container.lastModificationDate() > cached_container.lastModificationDate()) {
        return true;
    }
    return false;
}

void KvdbProvider::updateStats(const server::KvdbStatsEventData& stats) {
    auto kvdbInfo = this->get(stats.kvdbId()).container;
    updateByValue(kvdbInfo);
}