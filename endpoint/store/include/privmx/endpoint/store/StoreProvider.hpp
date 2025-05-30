/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_STOREPROVIDER_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_STORECACHE_HPP_

#include <privmx/endpoint/core/ContainerProvider.hpp>
#include "privmx/endpoint/store/ServerTypes.hpp"
#include "privmx/endpoint/store/StoreException.hpp"

namespace privmx {
namespace endpoint {
namespace store {

class StoreProvider : public core::ContainerProvider<std::string, server::Store> {
public:
    StoreProvider(std::function<server::Store(std::string)> getStore, std::function<uint32_t(server::Store)> validateStore);
    void updateStats(const server::StoreStatsChangedEventData& stats);
protected:
    bool isNewerOrSameAsInStorage(const server::Store& container) override;
    inline std::string getID(const server::Store& container) override {return container.id();}
};

} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_STOREPROVIDER_HPP_