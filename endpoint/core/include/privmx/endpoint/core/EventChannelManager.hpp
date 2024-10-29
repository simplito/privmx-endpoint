#ifndef _PRIVMXLIB_ENDPOINT_CORE_EVENT_CHANNEL_MANAGER_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_EVENT_CHANNEL_MANAGER_HPP_

#include <privmx/privfs/gateway/RpcGateway.hpp>
#include <privmx/utils/ThreadSaveMap.hpp>
#include <string>

#include "privmx/endpoint/core/EventMiddleware.hpp"

namespace privmx {
namespace endpoint {
namespace core {

class EventChannelManager {
public:
    EventChannelManager(privfs::RpcGateway::Ptr gateway, std::shared_ptr<EventMiddleware> eventMiddleware);
    void subscribeFor(std::string channel);
    void unsubscribeFrom(std::string channel);

private:
    privfs::RpcGateway::Ptr _gateway;
    std::shared_ptr<EventMiddleware> _eventMiddleware;
    utils::ThreadSaveMap<std::string, uint64_t> _map;
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_EVENT_CHANNEL_MANAGER_HPP_