/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_THREAD_THREADCACHE_HPP_
#define _PRIVMXLIB_ENDPOINT_THREAD_THREADCACHE_HPP_

#include <privmx/endpoint/core/Cache.hpp>
#include "privmx/endpoint/thread/ServerTypes.hpp"
#include "privmx/endpoint/thread/ThreadException.hpp"

namespace privmx {
namespace endpoint {
namespace thread {

class ThreadCache : public core::Cache<std::string, server::ThreadInfo> {
public:
    ThreadCache(std::function<server::ThreadInfo(std::string)> getThread);
    void update(const std::string& id, const server::ThreadInfo& value) override;
};

} // thread
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_THREAD_THREADCACHE_HPP_