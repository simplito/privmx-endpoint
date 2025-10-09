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

#ifndef PRIVMX_EXECUTOR_THREAD_POOL_SIZE
#define PRIVMX_EXECUTOR_THREAD_POOL_SIZE 4
#endif

namespace privmx {
namespace utils {

class Executor
{
public:
    static Executor& getInstance() {
        static Executor inst;
        return inst;
    }
    ~Executor();
    void exec(std::function<void()> task);
private:
    Executor();

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
    void initializeThreadPool();

    std::shared_ptr<privmx::utils::ThreadSafeQueue<TaskData>> _tasksToDo;
    std::vector<ExecutorThread> _threadPool;
};

} // utils
} // privmx

#endif

