#ifndef _PRIVMXLIB_ENDPOINT_CORE_HANDLE_MANAGER_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_HANDLE_MANAGER_HPP_

#include <atomic>
#include <string>
#include <privmx/utils/ThreadSaveMap.hpp>

namespace privmx {
namespace endpoint {
namespace core {

class HandleManager {
public:
    HandleManager() = default;
    int64_t createHandle(std::string label);
    std::string getHandleLabel(int64_t id);
    void removeHandle(int64_t id);
private:
    std::atomic_int64_t _id = 0;
    utils::ThreadSaveMap<int64_t, std::string> _map;
};

} // core
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_HANDLE_MANAGER_HPP_