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
