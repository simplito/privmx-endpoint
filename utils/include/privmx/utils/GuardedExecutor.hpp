/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef PRIVMX_UTILS_GUARDEDEXECUTOR_HPP
#define PRIVMX_UTILS_GUARDEDEXECUTOR_HPP


#include "privmx/utils/Executor.hpp"
#include <atomic>
#include <memory>
#include <mutex>
#include <functional>
#include <condition_variable>


namespace privmx {
namespace utils {

class GuardedExecutor
{
public:
    GuardedExecutor();
    ~GuardedExecutor();
    void exec(std::function<void()> task);
private:
    bool isBusy();
    void waitToStopDataProcessing();
    uint64_t _dataToProcess;
    std::atomic_bool _stopping;
    std::condition_variable _allDataProcessed;
    std::mutex _dataToProcessMutex;
};

} // utils
} // privmx

#endif

