/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/


#include "privmx/utils/Executor.hpp"
#include "privmx/utils/Logger.hpp"
using namespace privmx::utils;

Executor::Executor() : _tasksToDo(std::make_shared<privmx::utils::ThreadSafeQueue<TaskData>>()) {
    initializeThreadPool();
}

Executor::~Executor() {
    LOG_INFO("Executor stopping ", PRIVMX_EXECUTOR_THREAD_POOL_SIZE, " threads")
    _tasksToDo->clear();
    for(auto& executorThread: _threadPool) {
        executorThread.token->cancel();
        _tasksToDo->push(TaskData{.type = TaskType::STOP, .callback = std::function<void()>()});
    }
    for(auto& executorThread: _threadPool) {
        if(executorThread.thread.joinable()) {
            LOG_TRACE("Executor thread join")
            executorThread.thread.join();
        }
    }
}

void Executor::exec(std::function<void()> task) {
    _tasksToDo->push(TaskData{.type = TaskType::NORMAL, .callback = task});
}

void Executor::createThread() {
    privmx::utils::CancellationToken::Ptr cancellation_token = privmx::utils::CancellationToken::create();
    std::thread thread = std::thread([](privmx::utils::CancellationToken::Ptr token, std::shared_ptr<privmx::utils::ThreadSafeQueue<TaskData>> tasks) {
        LOG_DEBUG("Executor thread started")
        while(!token->isCancelled()) {
            try {
                LOG_TRACE("Executor waiting for task")
                auto task = tasks->pop();
                if(task.type == TaskType::STOP || token->isCancelled()) {
                    break;
                }
                task.callback();
            } catch (const std::exception& e) {
                LOG_ERROR("Executor thread catch'ed exception '", e.what(), "' when processing task")
            } catch (...) {
                LOG_ERROR("Executor thread catch'ed unknown exception when processing task")
            }
        }
        LOG_DEBUG("Executor thread stopped")
    }, cancellation_token, _tasksToDo);
    _threadPool.push_back(
        ExecutorThread{
            .thread = std::move(thread),
            .token = cancellation_token
        }
    );
}

void Executor::initializeThreadPool() {
    LOG_INFO("Executor initializing with ", PRIVMX_EXECUTOR_THREAD_POOL_SIZE, " threads")
    for(size_t i = _threadPool.size(); i < PRIVMX_EXECUTOR_THREAD_POOL_SIZE; i++) {
        createThread();
    }
}


