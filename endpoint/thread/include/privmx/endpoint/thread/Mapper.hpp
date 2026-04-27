/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_THREAD_MAPPER_HPP_
#define _PRIVMXLIB_ENDPOINT_THREAD_MAPPER_HPP_

#include "privmx/endpoint/thread/Events.hpp"
#include "privmx/endpoint/thread/ServerTypes.hpp"

namespace privmx {
namespace endpoint {
namespace thread {

class Mapper {
public:
    static ThreadDeletedEventData mapToThreadDeletedEventData(const server::ThreadDeletedEventData_c_struct& data);
    static ThreadDeletedMessageEventData mapToThreadDeletedMessageEventData(const server::ThreadDeletedMessageEventData_c_struct& data);
    static ThreadStatsEventData mapToThreadStatsEventData(const server::ThreadStatsEventData_c_struct& data);
};

}  // namespace thread
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_THREAD_MAPPER_HPP_
