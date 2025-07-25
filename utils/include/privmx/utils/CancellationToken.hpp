/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_UTILS_CANCELLATIONTOKEN_HPP_
#define _PRIVMXLIB_UTILS_CANCELLATIONTOKEN_HPP_

#include <atomic>
#include <chrono>
#include <functional>
#include <unordered_map>
#include <vector>
#include <Poco/SharedPtr.h>
#include <iostream>

#include <privmx/utils/PrivmxExtExceptions.hpp>
#include <privmx/utils/Types.hpp>

namespace privmx {
namespace utils {

class CancellationToken
{
public:
    using Ptr = Poco::SharedPtr<CancellationToken>;

    class Task
    {
    public:
        Task();
        Task(CancellationToken::Ptr token, const std::function<void(void)>& func);
        ~Task();

    private:
        CancellationToken::Ptr _token;
        int _id = -1;
    };

    static CancellationToken::Ptr create();
    static CancellationToken::Ptr create(CancellationToken::Ptr token);
    CancellationToken();
    CancellationToken(CancellationToken::Ptr token);
    ~CancellationToken();
    void cancel();
    bool isCancelled();
    void validate();
    template<typename Rep, typename Period>
    void sleep(const std::chrono::duration<Rep, Period>& duration);


private:
    int registerTask(const std::function<void(void)>& func);
    void unregisterTask(int id);
    void throwOperationCanceled();

    std::atomic_bool _cancelled;
    Mutex _mutex;
    ConditionVariable _cv;
    int _id = 0;
    std::unordered_map<int, std::function<void(void)>> _tasks;
    Task _parent;
};

inline bool CancellationToken::isCancelled() {
    std::cerr << "CancellationToken isCancelled: " << this << std::endl; // Debug by Patryk
    return _cancelled.load();
}

inline void CancellationToken::validate() {
    std::cerr << "CancellationToken validate: " << this << std::endl; // Debug by Patryk
    if (isCancelled()) {
        throwOperationCanceled();
    }
}

inline void CancellationToken::throwOperationCanceled() {
    throw OperationCancelledException();
}

template<typename Rep, typename Period>
inline void CancellationToken::sleep(const std::chrono::duration<Rep, Period>& duration) {
    std::cerr << "CancellationToken sleep: " << this << std::endl; // Debug by Patryk
    UniqueLock lock(_mutex);
    if (_cancelled) {
        throwOperationCanceled();
    }
    auto status = _cv.wait_for(lock, duration);
    if (status == std::cv_status::no_timeout) {
        throwOperationCanceled();
    }
}

} // utils
} // privmx

#endif // _PRIVMXLIB_UTILS_CANCELLATIONTOKEN_HPP_
