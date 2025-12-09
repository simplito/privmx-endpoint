


#include "privmx/utils/logger/Outputs.hpp"



#ifdef PRIVMX_ENABLE_LOGGER
using namespace privmx::logger;

void BaseLoggerOutput::log(LogLevel level, const std::string& message) {
    outputMessageLog(
        #ifdef PRIVMX_LOGGER_OUTPUT_INCLUDE_TIMESTAMP
            createTimestampString() + " " + 
        #endif
        #ifdef PRIVMX_LOGGER_OUTPUT_INCLUDE_THREADID
            createThisThreadIdString() + " " +
        #endif
        createLevelString(level, true) + " " + 
        message
    );
}
#ifdef PRIVMX_LOGGER_OUTPUT_FILE
void FileLoggerOutput::log(LogLevel level, const std::string& message) {
    outputMessageLog(
        #ifdef PRIVMX_LOGGER_OUTPUT_INCLUDE_TIMESTAMP
            createTimestampString() + " " + 
        #endif
        #ifdef PRIVMX_LOGGER_OUTPUT_INCLUDE_THREADID
            createThisThreadIdString() + " " +
        #endif
        createLevelString(level, false) + " " + 
        message
    );
}
#endif

#ifdef PRIVMX_LOGGER_OUTPUT_INCLUDE_TIMESTAMP
#include <ctime>
std::string BaseLoggerOutput::createTimestampString() {
    std::time_t now = std::time(nullptr);
    char buf[20];
    std::strftime(buf, sizeof(buf), "%F %T", std::localtime(&now));
    return buf;
}
#endif
#ifdef PRIVMX_LOGGER_OUTPUT_INCLUDE_THREADID
#include <sstream>
#include <thread>
std::string BaseLoggerOutput::createThisThreadIdString() {
    auto myid = std::this_thread::get_id();
    std::stringstream ss;
    ss << "{TID:" << myid << "}";
    return ss.str();
}
#endif
std::string BaseLoggerOutput::createLevelString(LogLevel level, bool addTerminalColors) {
    return addTerminalColors ? 
        (levelToColor(level) + "[PRIVMX "+levelToString(level)+"]" + "\033[00m") :
        ( "[PRIVMX "+levelToString(level)+"]");
}

std::string BaseLoggerOutput::levelToString(LogLevel level) {
    switch (level) {
        case LogLevel::TRACE: return "TRACE";
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO:  return " INFO";
        case LogLevel::WARN:  return " WARN";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::FATAL: return "FATAL";
        default: return "UNKNOWN";
    }
}
std::string BaseLoggerOutput::levelToColor(LogLevel level) {
    switch (level) {
        case LogLevel::TRACE: return "\033[90m";
        case LogLevel::DEBUG: return "\033[00m";
        case LogLevel::INFO:  return "\033[94m";
        case LogLevel::WARN:  return "\033[93m";
        case LogLevel::ERROR: return "\033[91m";
        case LogLevel::FATAL: return "\033[35m";
        default: return "\033[00m";
    }
}

#endif // PRIVMX_ENABLE_LOGGER