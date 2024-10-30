#ifndef _PRIVMXLIB_ENDPOINT_STORE_MAPPER_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_MAPPER_HPP_

#include "privmx/endpoint/store/Events.hpp"
#include "privmx/endpoint/store/ServerTypes.hpp"

namespace privmx {
namespace endpoint {
namespace store {

class Mapper {
public:
    static StoreDeletedEventData mapToStoreDeletedEventData(const server::StoreDeletedEventData& data);
    static StoreFileDeletedEventData mapToStoreFileDeletedEventData(const server::StoreFileDeletedEventData& data);
    static StoreStatsChangedEventData mapToStoreStatsChangedEventData(const server::StoreStatsChangedEventData& data);
};

}  // namespace store
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_STORE_MAPPER_HPP_
