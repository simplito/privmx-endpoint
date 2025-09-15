/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_UTILS_THREAD_SAVE_MAP_HPP_
#define _PRIVMXLIB_UTILS_THREAD_SAVE_MAP_HPP_

#include <map>
#include <optional>
#include <mutex>
#include <shared_mutex>
#include <functional>
#include <iostream>


namespace privmx {
namespace utils {

template <typename KEY, typename VALUE>
class ThreadSaveMap {
public:
    ThreadSaveMap() {}
    ThreadSaveMap(const ThreadSaveMap& threadSaveMap): _map(threadSaveMap._map) {}
    std::optional<VALUE> get(KEY key);
    void set(KEY key, VALUE value);
    void erase(KEY key);
    void clear();
    void forAll(const std::function<void(const KEY&, const VALUE&)>& func);
    void updateValueIfExist(KEY key, const std::function<VALUE(const VALUE&)>& func);
    bool has(KEY key);
    size_t size();

private:
    std::shared_mutex _map_mutex;
    std::map<KEY, VALUE> _map;
};

template <typename KEY, typename VALUE> 
inline std::optional<VALUE> ThreadSaveMap<KEY, VALUE>::get(KEY key) {
    std::shared_lock<std::shared_mutex> lock(_map_mutex);
    auto search = _map.find(key);
    if (search == _map.end()) {
        return std::nullopt;
    }
    return search->second;
}

template <typename KEY, typename VALUE> 
inline void ThreadSaveMap<KEY, VALUE>::set(KEY key, VALUE value) {
    std::unique_lock<std::shared_mutex> lock(_map_mutex);
    _map[key] = value;
}

template <typename KEY, typename VALUE> 
inline void ThreadSaveMap<KEY, VALUE>::erase(KEY key) {
    std::unique_lock<std::shared_mutex> lock(_map_mutex);
    _map.erase(key);

}
template <typename KEY, typename VALUE> 
inline void ThreadSaveMap<KEY, VALUE>::clear() {
    std::unique_lock<std::shared_mutex> lock(_map_mutex);
    _map.clear();
}

template <typename KEY, typename VALUE>
inline void ThreadSaveMap<KEY, VALUE>::forAll(const std::function<void(const KEY&, const VALUE&)>& func) {
    std::shared_lock<std::shared_mutex> lock(_map_mutex);
    std::for_each(_map.begin(), _map.end(), [&](const auto& p) {func(p.first, p.second);});
}

template <typename KEY, typename VALUE>
inline void ThreadSaveMap<KEY, VALUE>::updateValueIfExist(KEY key, const std::function<VALUE(const VALUE&)>& func) {
    std::unique_lock<std::shared_mutex> lock(_map_mutex);
    auto search = _map.find(key);
    if (search != _map.end()) {
        _map[key] = func(search->second);
    }
}

template <typename KEY, typename VALUE>
inline bool ThreadSaveMap<KEY, VALUE>::has(KEY key) {
    std::shared_lock<std::shared_mutex> lock(_map_mutex);
    auto result = _map.find(key); 
    return result != _map.end();
}

template <typename KEY, typename VALUE>
inline size_t ThreadSaveMap<KEY, VALUE>::size() {
    std::shared_lock<std::shared_mutex> lock(_map_mutex);
    return _map.size();
}

} // utils
} // privmx

#endif // _PRIVMXLIB_UTILS_THREAD_SAVE_MAP_HPP_
