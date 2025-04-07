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
    ThreadProvider(std::function<server::ThreadInfo(std::string)> getThread, std::function<uint32_t(server::ThreadInfo)> validateThread);
    void updateStats(const server::ThreadStatsEventData& stats);
protected:
    bool isNewerOrSameAsInStorage(const server::ThreadInfo& container) override;
    inline std::string getID(const server::ThreadInfo& container) override {return container.id();}
};

} // thread
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_THREAD_THREADPROVIDER_HPP_