/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/utils/GuardedExecutor.hpp"
#include "privmx/utils/Logger.hpp"

using namespace privmx::utils;

GuardedExecutor::GuardedExecutor() : _dataToProcess(0), _stopping(false) {}

GuardedExecutor::~GuardedExecutor() {
    waitToStopDataProcessing();
    LOG_TRACE("GuardedExecutor deconstructed");
}

void GuardedExecutor::exec(std::function<void()> task) {
    if(_stopping) {
        return;
    }
    {
        std::unique_lock<std::mutex> lock(_dataToProcessMutex);
        ++_dataToProcess;
    }
    privmx::utils::Executor::getInstance()->exec([&, task]() {
        try {
            task();
        } catch (const std::exception& e) {
            LOG_ERROR("GuardedExecutor thread catch'ed exception '", e.what(), "' when processing task")
        } catch (...) {
            LOG_ERROR("GuardedExecutor thread catch'ed unknown exception when processing task")
        }
        {
            std::unique_lock<std::mutex> lock(_dataToProcessMutex);
            --_dataToProcess;
            if(_stopping && _dataToProcess == 0) {
                _allDataProcessed.notify_all();
            }
        }
    });
}

bool GuardedExecutor::isBusy() {
    LOG_TRACE("GuardedExecutor dataToProcess ", _dataToProcess);
    return _dataToProcess != 0;
}

void GuardedExecutor::waitToStopDataProcessing() {
    _stopping = true;
    std::unique_lock<std::mutex> lock(_dataToProcessMutex);
    _allDataProcessed.wait(lock, [&]{ return isBusy() == 0; });
}
