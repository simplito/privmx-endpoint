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

StoreProvider::StoreProvider(std::function<server::Store(std::string)> getStore) : core::ContainerProvider<std::string, server::Store>(getStore) {}
    
void StoreProvider::updateByValue( const server::Store& container) {
    auto cached = _storage.get(container.id());
    if(!cached.has_value()) {
        _storage.set(container.id(), container);
        return;
    }
    auto cached_container = cached.value();
    if(container.version() > cached_container.version()) {
        _storage.set(container.id(), container);
    } else if (container.version() == cached_container.version() && container.lastModificationDate() > cached_container.lastModificationDate()) {
        _storage.set(container.id(), container);
    }
}

void StoreProvider::updateStats(const server::StoreStatsChangedEventData& stats) {
    auto store = this->get(stats.id());
    store.files(stats.files());
    store.lastFileDate(stats.lastFileDate());
    updateByValue(store);
}