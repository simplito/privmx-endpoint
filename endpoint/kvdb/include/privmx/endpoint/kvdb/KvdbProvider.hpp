/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_KVDB_KVDBPROVIDER_HPP_
#define _PRIVMXLIB_ENDPOINT_KVDB_KVDBPROVIDER_HPP_

#include <privmx/endpoint/core/ContainerProvider.hpp>
#include "privmx/endpoint/kvdb/ServerTypes.hpp"
#include "privmx/endpoint/kvdb/KvdbException.hpp"

namespace privmx {
namespace endpoint {
namespace kvdb {

class KvdbProvider : public core::ContainerProvider<std::string, server::KvdbInfo> {
public:
    KvdbProvider(std::function<server::KvdbInfo(std::string)> getKvdb, std::function<uint32_t(server::KvdbInfo)> validateKvdb);
    void updateStats(const server::KvdbStatsEventData& stats);
protected:
    bool isNewerOrSameAsInStorage(const server::KvdbInfo& container) override;
    inline std::string getID(const server::KvdbInfo& container) override {return container.id();}
};

} // kvdb
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_KVDB_KVDBPROVIDER_HPP_