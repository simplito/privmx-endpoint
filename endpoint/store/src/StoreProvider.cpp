/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/store/StoreProvider.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::store;

StoreProvider::StoreProvider(std::function<server::Store(std::string)> getStore, std::function<uint32_t(server::Store)> validateStore)
     : core::ContainerProvider<std::string, server::Store>(getStore, validateStore) {}
    
bool StoreProvider::isNewerOrSameAsInStorage( const server::Store& container) {
    auto cached = _storage.get(container.id());
    if(!cached.has_value()) {
        return true;
    }
    auto cached_container = cached.value().container;
    if (container.version() > cached_container.version() ||
        (container.lastModificationDate() >= cached_container.lastModificationDate() && container.version() == cached_container.version())
    ) {
            return true;
    }
    return false;
}

void StoreProvider::updateStats(const server::StoreStatsChangedEventData& stats) {
    auto store = this->get(stats.id()).container;
    store.files(stats.files());
    store.lastFileDate(stats.lastFileDate());
    updateByValue(store);
}