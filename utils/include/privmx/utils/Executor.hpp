/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef PRIVMX_UTILS_EXECUTOR_HPP
#define PRIVMX_UTILS_EXECUTOR_HPP

#include <vector>
#include <functional>
#include <thread>
#include <optional>

#include "privmx/utils/CancellationToken.hpp"
#include "privmx/utils/ThreadSafeQueue.hpp"
#include "privmx/utils/ExecutorConfig.hpp"
#include "privmx/utils/Logger.hpp"

#ifndef PRIVMX_EXECUTOR_THREAD_POOL_SIZE
#define PRIVMX_EXECUTOR_THREAD_POOL_SIZE 4
#endif

namespace privmx {
namespace utils {

class Executor
{
public:
    static std::shared_ptr<Executor> getInstance();
    static void freeInstance();
    Executor(const Executor& obj) = delete; 
    void operator=(const Executor &) = delete;
    ~Executor();
    void exec(std::function<void()> task);
protected:
    Executor();
private:
    enum TaskType {
        STOP = 0,
        NORMAL = 1
    };
    struct TaskData {
        TaskType type;
        std::function<void()> callback;
    };

    struct ExecutorThread {
        std::thread thread;
        privmx::utils::CancellationToken::Ptr token;
    };
    
    void createThread();
    void stopAllThreadInThePool();
    void initializeThreadPool();

    static std::shared_ptr<Executor> impl;
    std::shared_ptr<privmx::utils::ThreadSafeQueue<TaskData>> _tasksToDo;
    std::vector<ExecutorThread> _threadPool;
};

} // utils
} // privmx

#endif

