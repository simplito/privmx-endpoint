
#ifndef _PRIVMXLIB_UTILS_PRIVMX_LOGGER_PRINTER_HPP_
#define _PRIVMXLIB_UTILS_PRIVMX_LOGGER_PRINTER_HPP_

#include <privmx/utils/logger/Config.hpp>

#ifdef PRIVMX_ENABLE_LOGGER

#include "privmx/utils/logger/Core.hpp"
#include <iostream>
#include <fstream>
#include <memory>
#include <string>


namespace privmx {
namespace logger {


class BaseLoggerOutput : public LoggerOutput {
    public: 
        virtual void log(LogLevel level, const std::string& message);
    protected:
        #ifdef PRIVMX_LOGGER_OUTPUT_INCLUDE_TIMESTAMP
            std::string createTimestampString();
        #endif
        #ifdef PRIVMX_LOGGER_OUTPUT_INCLUDE_THREADID
            std::string createThisThreadIdString();
        #endif
        std::string createLevelString(LogLevel level, bool addTerminalColors);
        std::string levelToString(LogLevel level);
        std::string levelToColor(LogLevel level);
        virtual void outputMessageLog(const std::string& message) = 0;
};

#ifdef PRIVMX_LOGGER_OUTPUT_STDOUT
    class CoutLoggerOutput : public BaseLoggerOutput {
    protected:
        inline void outputMessageLog(const std::string& message) override {
            std::cout << message << std::endl;
        }
    };
#endif

#ifdef PRIVMX_LOGGER_OUTPUT_STDERR
    class CerrLoggerOutput : public BaseLoggerOutput {
    protected:
        inline void outputMessageLog(const std::string& message) override {
            std::cerr << message << std::endl;
        }
    };
#endif

#ifdef PRIVMX_LOGGER_OUTPUT_FILE
    class FileLoggerOutput : public BaseLoggerOutput {
    public:
        explicit FileLoggerOutput(const std::string& filename)
            : _file(filename, std::ios::out | std::ios::trunc) {}
        virtual void log(LogLevel level, const std::string& message);
    protected:
        inline void outputMessageLog(const std::string& message) override {
            if (_file.is_open()) {
                _file << message << std::endl;
            }
        }

    private:
        std::ofstream _file;
    };
    #ifndef PRIVMX_LOGGER_OUTPUT_FILE_PATH 
        #define PRIVMX_LOGGER_OUTPUT_FILE_PATH "log.txt"
    #endif
#endif


} // namespace logger
} // namespace privmx

#endif
#endif // _PRIVMXLIB_UTILS_PRIVMX_LOGGER_PRINTER_HPP_