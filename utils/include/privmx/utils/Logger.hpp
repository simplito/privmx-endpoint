
#ifndef _PRIVMXLIB_UTILS_PRIVMX_LOGGER_HPP_
#define _PRIVMXLIB_UTILS_PRIVMX_LOGGER_HPP_

#include <privmx/utils/logger/Config.hpp>

#ifdef PRIVMX_ENABLE_LOGGER

#ifndef PRIVMX_LOGGER_LEVEL
#define PRIVMX_LOGGER_LEVEL 4
#endif

#if !(defined(PRIVMX_LOGGER_OUTPUT_STDOUT) || defined(PRIVMX_LOGGER_OUTPUT_STDERR) || defined(PRIVMX_LOGGER_OUTPUT_FILE))
#define PRIVMX_LOGGER_OUTPUT_STDOUT
#endif

#include "privmx/utils/logger/Core.hpp"
#include "privmx/utils/logger/Outputs.hpp"

#if PRIVMX_LOGGER_LEVEL >= 6
    #define LOG_TRACE(...) privmx::logger::Logger::getInstance()->log(privmx::logger::LogLevel::TRACE, __VA_ARGS__);
    #ifdef PRIVMX_ENABLE_LOGGER_TIMER
        #define LOG_TIME_TRACE_START(LABEL, ...) privmx::logger::Logger::getInstance()->logTimerStart(privmx::logger::LogLevel::TRACE, #LABEL, __VA_ARGS__);
        #define LOG_TIME_TRACE_CHECKPOINT(LABEL, ...) privmx::logger::Logger::getInstance()->logTimerCheckpoint(privmx::logger::LogLevel::TRACE, #LABEL, __VA_ARGS__);
        #define LOG_TIME_TRACE_STOP(LABEL, ...) privmx::logger::Logger::getInstance()->logTimerStop(privmx::logger::LogLevel::TRACE, #LABEL, __VA_ARGS__);
    #else
        #define LOG_TIME_TRACE_START(LABEL, ...)
        #define LOG_TIME_TRACE_CHECKPOINT(LABEL, ...)
        #define LOG_TIME_TRACE_STOP(LABEL, ...)
    #endif
#else
    #define LOG_TRACE(...)
    #define LOG_TIME_TRACE_START(LABEL, ...)
    #define LOG_TIME_TRACE_CHECKPOINT(LABEL, ...)
    #define LOG_TIME_TRACE_STOP(LABEL, ...)
#endif

#if PRIVMX_LOGGER_LEVEL >= 5
    #define LOG_DEBUG(...) privmx::logger::Logger::getInstance()->log(privmx::logger::LogLevel::DEBUG, __VA_ARGS__);
    #ifdef PRIVMX_ENABLE_LOGGER_TIMER
        #define LOG_TIME_DEBUG_START(LABEL, ...) privmx::logger::Logger::getInstance()->logTimerStart(privmx::logger::LogLevel::DEBUG, #LABEL, __VA_ARGS__);
        #define LOG_TIME_DEBUG_CHECKPOINT(LABEL, ...) privmx::logger::Logger::getInstance()->logTimerCheckpoint(privmx::logger::LogLevel::DEBUG, #LABEL, __VA_ARGS__);
        #define LOG_TIME_DEBUG_STOP(LABEL, ...) privmx::logger::Logger::getInstance()->logTimerStop(privmx::logger::LogLevel::DEBUG, #LABEL, __VA_ARGS__);
    #else
        #define LOG_TIME_DEBUG_START(LABEL, ...)
        #define LOG_TIME_DEBUG_CHECKPOINT(LABEL, ...)
        #define LOG_TIME_DEBUG_STOP(LABEL, ...)
    #endif
#else
    #define LOG_DEBUG(...)
    #define LOG_TIME_DEBUG_START(LABEL, ...)
    #define LOG_TIME_DEBUG_CHECKPOINT(LABEL, ...)
    #define LOG_TIME_DEBUG_STOP(LABEL, ...)
#endif

#if PRIVMX_LOGGER_LEVEL >= 4
    #define LOG_INFO(...)  privmx::logger::Logger::getInstance()->log(privmx::logger::LogLevel::INFO, __VA_ARGS__);
    #ifdef PRIVMX_ENABLE_LOGGER_TIMER
        #define LOG_TIME_INFO_START(LABEL, ...) privmx::logger::Logger::getInstance()->logTimerStart(privmx::logger::LogLevel::INFO, #LABEL, __VA_ARGS__);
        #define LOG_TIME_INFO_CHECKPOINT(LABEL, ...) privmx::logger::Logger::getInstance()->logTimerCheckpoint(privmx::logger::LogLevel::INFO, #LABEL, __VA_ARGS__);
        #define LOG_TIME_INFO_STOP(LABEL, ...) privmx::logger::Logger::getInstance()->logTimerStop(privmx::logger::LogLevel::INFO, #LABEL, __VA_ARGS__);
    #else
        #define LOG_TIME_INFO_START(LABEL, ...)
        #define LOG_TIME_INFO_CHECKPOINT(LABEL, ...)
        #define LOG_TIME_INFO_STOP(LABEL, ...)
    #endif
#else
    #define LOG_INFO(...)
    #define LOG_TIME_INFO_START(LABEL, ...)
    #define LOG_TIME_INFO_CHECKPOINT(LABEL, ...)
    #define LOG_TIME_INFO_STOP(LABEL, ...)
#endif

#if PRIVMX_LOGGER_LEVEL >= 3
    #define LOG_WARN(...)  privmx::logger::Logger::getInstance()->log(privmx::logger::LogLevel::WARN, __VA_ARGS__);
    #ifdef PRIVMX_ENABLE_LOGGER_TIMER
        #define LOG_TIME_WARN_START(LABEL, ...) privmx::logger::Logger::getInstance()->logTimerStart(privmx::logger::LogLevel::WARN, #LABEL, __VA_ARGS__);
        #define LOG_TIME_WARN_CHECKPOINT(LABEL, ...) privmx::logger::Logger::getInstance()->logTimerCheckpoint(privmx::logger::LogLevel::WARN, #LABEL, __VA_ARGS__);
        #define LOG_TIME_WARN_STOP(LABEL, ...) privmx::logger::Logger::getInstance()->logTimerStop(privmx::logger::LogLevel::WARN, #LABEL, __VA_ARGS__);
    #else
        #define LOG_TIME_WARN_START(LABEL, ...)
        #define LOG_TIME_WARN_CHECKPOINT(LABEL, ...)
        #define LOG_TIME_WARN_STOP(LABEL, ...)
    #endif
#else
    #define LOG_WARN(...)
    #define LOG_TIME_WARN_START(LABEL, ...)
    #define LOG_TIME_WARN_CHECKPOINT(LABEL, ...)
    #define LOG_TIME_WARN_STOP(LABEL, ...)
#endif

#if PRIVMX_LOGGER_LEVEL >= 2
    #define LOG_ERROR(...) privmx::logger::Logger::getInstance()->log(privmx::logger::LogLevel::ERROR, __VA_ARGS__);
    #ifdef PRIVMX_ENABLE_LOGGER_TIMER
        #define LOG_TIME_ERROR_START(LABEL, ...) privmx::logger::Logger::getInstance()->logTimerStart(privmx::logger::LogLevel::ERROR, #LABEL, __VA_ARGS__);
        #define LOG_TIME_ERROR_CHECKPOINT(LABEL, ...) privmx::logger::Logger::getInstance()->logTimerCheckpoint(privmx::logger::LogLevel::ERROR, #LABEL, __VA_ARGS__);
        #define LOG_TIME_ERROR_STOP(LABEL, ...) privmx::logger::Logger::getInstance()->logTimerStop(privmx::logger::LogLevel::ERROR, #LABEL, __VA_ARGS__);
    #else
        #define LOG_TIME_ERROR_START(LABEL, ...)
        #define LOG_TIME_ERROR_CHECKPOINT(LABEL, ...)
        #define LOG_TIME_ERROR_STOP(LABEL, ...)
    #endif
#else
    #define LOG_ERROR(...)
    #define LOG_TIME_ERROR_START(LABEL, ...)
    #define LOG_TIME_ERROR_CHECKPOINT(LABEL, ...)
    #define LOG_TIME_ERROR_STOP(LABEL, ...)
#endif

#if PRIVMX_LOGGER_LEVEL >= 1
    #define LOG_FATAL(...) privmx::logger::Logger::getInstance()->log(privmx::logger::LogLevel::FATAL, __VA_ARGS__);
    #ifdef PRIVMX_ENABLE_LOGGER_TIMER
        #define LOG_TIME_FATAL_START(LABEL, ...) privmx::logger::Logger::getInstance()->logTimerStart(privmx::logger::LogLevel::FATAL, #LABEL, __VA_ARGS__);
        #define LOG_TIME_FATAL_CHECKPOINT(LABEL, ...) privmx::logger::Logger::getInstance()->logTimerCheckpoint(privmx::logger::LogLevel::FATAL, #LABEL, __VA_ARGS__);
        #define LOG_TIME_FATAL_STOP(LABEL, ...) privmx::logger::Logger::getInstance()->logTimerStop(privmx::logger::LogLevel::FATAL, #LABEL, __VA_ARGS__);
    #else
        #define LOG_TIME_FATAL_START(LABEL, ...)
        #define LOG_TIME_FATAL_CHECKPOINT(LABEL, ...)
        #define LOG_TIME_FATAL_STOP(LABEL, ...)
    #endif
#else
    #define LOG_FATAL(...)
    #define LOG_TIME_FATAL_START(LABEL, ...)
    #define LOG_TIME_FATAL_CHECKPOINT(LABEL, ...)
    #define LOG_TIME_FATAL_STOP(LABEL, ...)
#endif

#else 
    #define LOG_TRACE(...)
    #define LOG_TIME_TRACE_START(LABEL, ...)
    #define LOG_TIME_TRACE_CHECKPOINT(LABEL, ...)
    #define LOG_TIME_TRACE_STOP(LABEL, ...)
    
    #define LOG_DEBUG(...)
    #define LOG_TIME_DEBUG_START(LABEL, ...)
    #define LOG_TIME_DEBUG_CHECKPOINT(LABEL, ...)
    #define LOG_TIME_DEBUG_STOP(LABEL, ...)

    #define LOG_INFO(...)
    #define LOG_TIME_INFO_START(LABEL, ...)
    #define LOG_TIME_INFO_CHECKPOINT(LABEL, ...)
    #define LOG_TIME_INFO_STOP(LABEL, ...)

    #define LOG_WARN(...)
    #define LOG_TIME_WARN_START(LABEL, ...)
    #define LOG_TIME_WARN_CHECKPOINT(LABEL, ...)
    #define LOG_TIME_WARN_STOP(LABEL, ...)

    #define LOG_ERROR(...)
    #define LOG_TIME_ERROR_START(LABEL, ...)
    #define LOG_TIME_ERROR_CHECKPOINT(LABEL, ...)
    #define LOG_TIME_ERROR_STOP(LABEL, ...)

    #define LOG_FATAL(...)
    #define LOG_TIME_FATAL_START(LABEL, ...)
    #define LOG_TIME_FATAL_CHECKPOINT(LABEL, ...)
    #define LOG_TIME_FATAL_STOP(LABEL, ...)

#endif // PRIVMX_ENABLE_LOGGER

#endif // _PRIVMXLIB_UTILS_UTILS_HPP_