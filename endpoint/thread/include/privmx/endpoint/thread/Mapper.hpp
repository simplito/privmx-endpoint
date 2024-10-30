#ifndef _PRIVMXLIB_ENDPOINT_THREAD_MAPPER_HPP_
#define _PRIVMXLIB_ENDPOINT_THREAD_MAPPER_HPP_

#include "privmx/endpoint/thread/Events.hpp"
#include "privmx/endpoint/thread/ServerTypes.hpp"

namespace privmx {
namespace endpoint {
namespace thread {

class Mapper {
public:
    static ThreadDeletedEventData mapToThreadDeletedEventData(const server::ThreadDeletedEventData& data);
    static ThreadDeletedMessageEventData mapToThreadDeletedMessageEventData(const server::ThreadDeletedMessageEventData& data);
    static ThreadStatsEventData mapToThreadStatsEventData(const server::ThreadStatsEventData& data);
};

}  // namespace thread
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_THREAD_MAPPER_HPP_
