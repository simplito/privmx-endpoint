
#ifndef _PRIVMXLIB_UTILS_PRIVMX_LOGGER_CORE_HPP_
#define _PRIVMXLIB_UTILS_PRIVMX_LOGGER_CORE_HPP_

#include <privmx/utils/logger/Config.hpp>

#ifdef PRIVMX_ENABLE_LOGGER

#include <memory>
#include <shared_mutex>
#include <vector>
#include <string>
#include <mutex>
#include <sstream>
#include <chrono>
#include <utility>
#include <map>

namespace privmx {
namespace logger {

enum class LogLevel {
    TRACE = 6,
    DEBUG = 5,
    INFO = 4,
    WARN = 3,
    ERROR = 2,
    FATAL = 1,
    OFF = 0
};

class LoggerOutput {
public:
    virtual ~LoggerOutput() = default;
    virtual void log(LogLevel level, const std::string& message) = 0;
};

class Logger {
public:
    static Logger* instance();
    Logger(const Logger& obj) = delete; 
    void operator=(const Logger &) = delete;
    void addLoggerOutput(std::unique_ptr<LoggerOutput> output);
    inline bool hasLoggerOutputs() {return _outputs.size() != 0;}
    ~Logger();

    template<typename... Args>
    void log(LogLevel level, Args&&... args);
    #ifdef PRIVMX_ENABLE_LOGGER_TIMER
        template<typename... Args>
        void logTimerStart(LogLevel level, const std::string& label, Args&&... args);
        template<typename... Args>
        void logTimerCheckpoint(LogLevel level, const std::string& label, Args&&... args);
        template<typename... Args>
        void logTimerStop(LogLevel level, const std::string& label, Args&&... args);
    #endif
private:

    #ifdef PRIVMX_ENABLE_LOGGER_TIMER
        std::string timerStart(const std::string& label);
        std::string timerCheckpoint(const std::string& label);
        std::pair<std::string, std::string> timerStop(const std::string& label);
    #endif
    // Singleton
    Logger() = default;
    static Logger* impl;
    // Outputs
    std::mutex _mutex;
    std::vector<std::unique_ptr<LoggerOutput>> _outputs;
    // logTime
    #ifdef PRIVMX_ENABLE_LOGGER_TIMER
        std::map<std::string, std::chrono::time_point<std::chrono::system_clock>> _first_times;
        std::map<std::string, std::chrono::time_point<std::chrono::system_clock>> _last_times;
    #endif
};
template<typename... Args>
void Logger::log(LogLevel level, Args&&... args) {
    if (static_cast<int>(level) > PRIVMX_LOGGER_LEVEL || level == LogLevel::OFF) {
        return;
    }
    std::ostringstream oss;
    (oss << ... << args);
    std::lock_guard<std::mutex> lock(_mutex);

    for (auto& output : _outputs) {
        output->log(level, oss.str());
    }
}
#ifdef PRIVMX_ENABLE_LOGGER_TIMER
    template<typename... Args>
    void Logger::logTimerStart(LogLevel level, const std::string& label, Args&&... args) {
        log(level, timerStart(label), " | ", args...);
    }
    template<typename... Args>
    void Logger::logTimerCheckpoint(LogLevel level, const std::string& label, Args&&... args) {
        log(level, timerCheckpoint(label), " | ", args...);
    }
    template<typename... Args>
    void Logger::logTimerStop(LogLevel level, const std::string& label, Args&&... args) {
        auto tmp = timerStop(label);
        log(level, tmp.first, " | ", args...);
        log(level, tmp.second, " | ", args...);
    }
#endif




} // namespace logger
} // namespace privmx


#endif
#endif // _PRIVMXLIB_UTILS_UTILS_HPP_