/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_UTILS_DEBUG_HPP_
#define _PRIVMXLIB_UTILS_DEBUG_HPP_

#include <privmx/utils/DebugConfig.hpp>
#include <chrono>
#include <mutex>
#include <iostream>
#include <string>
#include <map>
#include <memory>
#include <iomanip>


#ifdef PRIVMX_USE_DEBUG

#ifdef PRIVMX_DEBUG_USE_CERR
    #define PRIVMX_DEBUG_OUTPUT_ARGS_6(ARG) \
        std::setw(20) << ARG 
    #define PRIVMX_DEBUG_OUTPUT_ARGS_5(ARG, ...) \
        std::setw(20) << ARG __VA_OPT__(<< PRIVMX_DEBUG_OUTPUT_ARGS_6(__VA_ARGS__))
    #define PRIVMX_DEBUG_OUTPUT_ARGS_4(ARG, ...) \
        std::setw(20) << ARG __VA_OPT__(<< PRIVMX_DEBUG_OUTPUT_ARGS_5(__VA_ARGS__))
    #define PRIVMX_DEBUG_OUTPUT_ARGS_3(ARG, ...) \
        std::setw(20) << ARG __VA_OPT__(<< PRIVMX_DEBUG_OUTPUT_ARGS_4(__VA_ARGS__))
    #define PRIVMX_DEBUG_OUTPUT_ARGS_2(ARG, ...) \
        std::setw(20) << ARG __VA_OPT__(<< PRIVMX_DEBUG_OUTPUT_ARGS_3(__VA_ARGS__))
    #define PRIVMX_DEBUG_OUTPUT_ARGS_1(ARG, ...) \
        std::setw(13) << ARG __VA_OPT__(<< PRIVMX_DEBUG_OUTPUT_ARGS_2(__VA_ARGS__))
    #define PRIVMX_DEBUG_OUTPUT(LABEL ,MSG, ...) \
        std::cerr << std::left << "[PRIVMX_DEBUG] " << std::setw(40) << LABEL << " - " << std::setw(28) << MSG __VA_OPT__( << PRIVMX_DEBUG_OUTPUT_ARGS_1(__VA_ARGS__)) << std::endl;

#else // PRIVMX_DEBUG_USE_CERR
    #define PRIVMX_DEBUG_OUTPUT_ARGS_6(ARG) \
        std::setw(20) << ARG 
    #define PRIVMX_DEBUG_OUTPUT_ARGS_5(ARG, ...) \
        std::setw(20) << ARG __VA_OPT__(<< PRIVMX_DEBUG_OUTPUT_ARGS_6(__VA_ARGS__))
    #define PRIVMX_DEBUG_OUTPUT_ARGS_4(ARG, ...) \
        std::setw(20) << ARG __VA_OPT__(<< PRIVMX_DEBUG_OUTPUT_ARGS_5(__VA_ARGS__))
    #define PRIVMX_DEBUG_OUTPUT_ARGS_3(ARG, ...) \
        std::setw(20) << ARG __VA_OPT__(<< PRIVMX_DEBUG_OUTPUT_ARGS_4(__VA_ARGS__))
    #define PRIVMX_DEBUG_OUTPUT_ARGS_2(ARG, ...) \
        std::setw(20) << ARG __VA_OPT__(<< PRIVMX_DEBUG_OUTPUT_ARGS_3(__VA_ARGS__))
    #define PRIVMX_DEBUG_OUTPUT_ARGS_1(ARG, ...) \
        std::setw(13) << ARG __VA_OPT__(<< PRIVMX_DEBUG_OUTPUT_ARGS_2(__VA_ARGS__))
    #define PRIVMX_DEBUG_OUTPUT(LABEL ,MSG, ...) \
        std::cout << std::left << "[PRIVMX_DEBUG] " << std::setw(40) << LABEL << " - " << std::setw(28) << MSG __VA_OPT__( << PRIVMX_DEBUG_OUTPUT_ARGS_1(__VA_ARGS__)) << std::endl;
#endif // PRIVMX_DEBUG_USE_CERR
namespace privmx {
namespace utils {
namespace debug {

class Debug {
public:
    static void print(const std::string& msg, const std::string& label, const std::string& group_name);
    static void print(const std::string& msg, const std::string& label);
    static void print(const std::string& msg);
    static void print(const int64_t& msg, const std::string& label, const std::string& group_name);
    static void print(const int64_t& msg, const std::string& label);
    static void print(const int64_t& msg);
};

#define PRIVMX_DEBUG_ARG_3(ARG,...) \
    ARG 
#define PRIVMX_DEBUG_ARG_2(ARG,...) \
    __VA_OPT__(PRIVMX_DEBUG_ARG_3(__VA_ARGS__), ) ARG
#define PRIVMX_DEBUG_ARG_1(ARG,...) \
    __VA_OPT__(PRIVMX_DEBUG_ARG_2(__VA_ARGS__), ) ARG


#define PRIVMX_DEBUG(...) \
    privmx::utils::debug::Debug::print( __VA_OPT__(PRIVMX_DEBUG_ARG_1(__VA_ARGS__)));

#ifdef PRIVMX_DEBUG_TIME


class DebugTimer {
public:
    DebugTimer(const std::string& group_and_test_label = "main:DebugTimer");
    static std::shared_ptr<DebugTimer> getInstance();
    void start(const std::string& group_name, const std::string& test_label, const std::string& msg = "");
    void checkpoint(const std::string& group_name, const std::string& test_label, const std::string& msg = "");
    void stop(const std::string& group_name, const std::string& test_label, const std::string& msg = "");
    void start(const std::string& test_label = "DebugTimer");
    void checkpoint(const std::string& test_label = "DebugTimer");
    void stop(const std::string& test_label = "DebugTimer");
private:
    void start_internal(const std::string& group_and_test_label = "main:DebugTimer", const std::string& msg = "");
    void checkpoint_internal(const std::string& group_and_test_label = "main:DebugTimer", const std::string& msg = "");
    void stop_internal(const std::string& group_and_test_label = "main:DebugTimer", const std::string& msg = "");

    static std::mutex _instance_mutex;
    static std::shared_ptr<DebugTimer> _instance;
    std::map<std::string, std::chrono::time_point<std::chrono::system_clock>> _first_times;
    std::map<std::string, std::chrono::time_point<std::chrono::system_clock>> _last_times;
};
#define PRIVMX_DEBUG_TIME_ARG_3(ARG,...) \
    #ARG 

#define PRIVMX_DEBUG_TIME_ARG_2(ARG,...) \
    #ARG __VA_OPT__(, PRIVMX_DEBUG_TIME_ARG_3(__VA_ARGS__))

#define PRIVMX_DEBUG_TIME_ARG_1(ARG,...) \
    #ARG __VA_OPT__(, PRIVMX_DEBUG_TIME_ARG_2(__VA_ARGS__))

#define PRIVMX_DEBUG_TIME_START(...) \
    privmx::utils::debug::DebugTimer::getInstance()->start( __VA_OPT__(PRIVMX_DEBUG_TIME_ARG_1(__VA_ARGS__)));
#define PRIVMX_DEBUG_TIME_CHECKPOINT(...) \
    privmx::utils::debug::DebugTimer::getInstance()->checkpoint( __VA_OPT__(PRIVMX_DEBUG_TIME_ARG_1(__VA_ARGS__)));
#define PRIVMX_DEBUG_TIME_STOP(...) \
    privmx::utils::debug::DebugTimer::getInstance()->stop( __VA_OPT__(PRIVMX_DEBUG_TIME_ARG_1(__VA_ARGS__)));



#else // PRIVMX_DEBUG_TIME
#define PRIVMX_DEBUG_TIME_START(...)
#define PRIVMX_DEBUG_TIME_CHECKPOINT(...)
#define PRIVMX_DEBUG_TIME_STOP(...)
#endif // PRIVMX_DEBUG_TIME

} // debug
} // utils
} // privmx

#else 
#define PRIVMX_DEBUG_TIME_START(...)
#define PRIVMX_DEBUG_TIME_CHECKPOINT(...)
#define PRIVMX_DEBUG_TIME_STOP(...)
#define PRIVMX_DEBUG(...)


#endif // PRIVMX_USE_DEBUG

#endif // _PRIVMXLIB_UTILS_UTILS_HPP_

