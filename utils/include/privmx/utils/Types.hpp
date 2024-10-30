#ifndef _PRIVMXLIB_UTILS_TYPES_HPP_
#define _PRIVMXLIB_UTILS_TYPES_HPP_

#include <any>
#include <condition_variable>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>
#include <shared_mutex>
#include <Poco/Types.h>
#include <functional>

#include <Pson/BinaryString.hpp>

namespace privmx {
namespace utils {

using Buffer = std::string;
using String = std::string;
using BinaryString = Pson::BinaryString;
using Int = Poco::Int64;
using UInt = Poco::UInt64;
template<typename T>
using Vector = std::vector<T>;
template<typename T1, typename T2>
using UnorderedMap = std::unordered_map<T1, T2>;

using Mutex = std::mutex;
using SharedMutex = std::shared_mutex;
using RecursiveMutex = std::recursive_mutex;

using Lock = std::lock_guard<Mutex>;
using RecursiveLock = std::lock_guard<RecursiveMutex>;
using SharedLockShared = std::shared_lock<SharedMutex>;
using UniqueLockShared = std::unique_lock<SharedMutex>;
using UniqueLock = std::unique_lock<Mutex>;
using ConditionVariable = std::condition_variable;

template<typename T>
using Opt = std::optional<T>;
using Any = std::any;

template<typename... T>
using Callback = std::function<void(const T&...)>;

} // utils
} // privmx

#endif // _PRIVMXLIB_UTILS_TYPES_HPP_
