/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_THREAD_THREADPROVIDER_HPP_
#define _PRIVMXLIB_ENDPOINT_THREAD_THREADPROVIDER_HPP_

#include <privmx/endpoint/core/ContainerProvider.hpp>
#include "privmx/endpoint/thread/ServerTypes.hpp"
#include "privmx/endpoint/thread/ThreadException.hpp"

namespace privmx {
namespace endpoint {
namespace thread {

class ThreadProvider : public core::ContainerProvider<std::string, server::ThreadInfo> {
public:
    ThreadProvider(std::function<server::ThreadInfo(std::string)> getThread);
    void updateCache(const std::string& id, const server::ThreadInfo& value) override;
};

} // thread
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_THREAD_THREADPROVIDER_HPP_