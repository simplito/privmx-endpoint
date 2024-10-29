#ifndef _PRIVMXLIB_UTILS_EVENTDISPATCHER_HPP_
#define _PRIVMXLIB_UTILS_EVENTDISPATCHER_HPP_

#include <functional>
#include <unordered_map>

#include <privmx/utils/Types.hpp>

namespace privmx {
namespace utils {

template<typename... T>
class EventDispatcher
{
public:
    int addEventListener(const Callback<T...>& callback, int listener_id = -1);
    void removeEventListener(int listener_id);
    void dispatch(const T&... val);

private:
    int _current_id = -2;
    std::unordered_map<int, Callback<T...>> _callbacks;
    Mutex _mutex;
};

template<typename... T>
inline int EventDispatcher<T...>::addEventListener(const Callback<T...>& callback, int listener_id) {
    int id = listener_id == -1 ? _current_id-- : listener_id;
    Lock lock(_mutex);
    _callbacks[id] = callback;
    return id;
}

template<typename... T>
inline void EventDispatcher<T...>::removeEventListener(int listener_id) {
    Lock lock(_mutex);
    _callbacks.erase(listener_id);
}

template<typename... T>
inline void EventDispatcher<T...>::dispatch(const T&... val) {
    std::unordered_map<int, Callback<T...>> callbacks_copy;
    {
        Lock lock(_mutex);
        callbacks_copy = _callbacks;
    }
    for (auto& callback : callbacks_copy) {
        if (callback.second) {
            try {
                callback.second(val...);
            } catch (...) {}
        }
    }
}

} // utils
} // privmx

#endif // _PRIVMXLIB_UTILS_EVENTDISPATCHER_HPP_
