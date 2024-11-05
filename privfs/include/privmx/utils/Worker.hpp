/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_UTILS_WORKER_HPP_
#define _PRIVMXLIB_UTILS_WORKER_HPP_

#include <atomic>
#include <functional>
#include <thread>

#include <privmx/utils/CancellationToken.hpp>
#include <privmx/utils/PrivmxException.hpp>

namespace privmx {
namespace utils {

class Worker
{
public:
    Worker();
    ~Worker();
    void start(const std::function<void(CancellationToken::Ptr)>& func, CancellationToken::Ptr token = CancellationToken::create());
    void stop();

private:
    void tryStop();

    std::atomic_bool _running;
    CancellationToken::Ptr _token;
    std::thread _thread;
};

} // utils
} // privmx

#endif // _PRIVMXLIB_UTILS_WORKER_HPP_
