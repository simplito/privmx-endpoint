


#include "privmx/utils/logger/Core.hpp"
#include "privmx/utils/logger/Outputs.hpp"
#include <iomanip>

#ifdef PRIVMX_ENABLE_LOGGER
using namespace privmx::logger;

Logger* Logger::impl = nullptr;
Logger* Logger::instance() {
    if(!impl) {
        impl = new Logger();
        INITIALIZE_PRIVMX_LOGGER_STDOUT
        INITIALIZE_PRIVMX_LOGGER_STDERR
        INITIALIZE_PRIVMX_LOGGER_FILE
    }
    return impl;
}

void Logger::addLoggerOutput(std::unique_ptr<LoggerOutput> output) {
    std::lock_guard<std::mutex> lock(_mutex);
    _outputs.push_back(std::move(output));
}

#ifdef PRIVMX_ENABLE_LOGGER_TIMER
std::string Logger::timerStart(const std::string& label) {
    if(std::chrono::system_clock::to_time_t(_first_times[label]) != 0) {
        log(LogLevel::WARN , label, "- Label is used reseting data");
    }
    _first_times[label] = std::chrono::system_clock::now();
    _last_times[label] = std::chrono::system_clock::now();
    std::ostringstream ss;
    ss << std::left << std::setw(40) << label << " - " << std::setw(28) << "Timer start" << std::setw(11) << " " ;
    return ss.str();
}

std::string Logger::timerCheckpoint(const std::string& label) {
    std::ostringstream ss;
    if(std::chrono::system_clock::to_time_t(_first_times[label]) == 0) {
        log(LogLevel::WARN , label, "- Label is not initialized");
        ss << std::left << std::setw(40) << label << " - " << std::setw(28) << "Time since last checkpoint" << std::setw(9) << "UNKNOWN" << "ms";
    } else {
        auto current_time = std::chrono::system_clock::now();
        const std::chrono::duration<double> diff = current_time - _last_times[label];
        _last_times[label] = current_time;
        ss << std::left << std::setw(40) << label << " - " << std::setw(28) << "Time since last checkpoint" << std::setw(9) << diff.count()*1000 <<"ms";
    } 
    return ss.str();
}

std::pair<std::string, std::string> Logger::timerStop(const std::string& label) {
    std::ostringstream ss_start;
    std::ostringstream ss_checkpoint;
    if(std::chrono::system_clock::to_time_t(_first_times[label]) == 0) {
        log(LogLevel::WARN , label, "- Label is not initialized");
        ss_start      << std::left << std::setw(40) << label << " - " << std::setw(28) << "Time since start" << std::setw(9) << "UNKNOWN" << "ms";
        ss_checkpoint << std::left << std::setw(40) << label << " - " << std::setw(28) << "Time since last checkpoint" << std::setw(9) << "UNKNOWN" << "ms";
        
    } else {
    auto current_time = std::chrono::system_clock::now();
    const std::chrono::duration<double> diff_checkpoint = current_time - _last_times[label];
    const std::chrono::duration<double> diff_start = current_time - _first_times[label];
    _last_times.erase(label);
    _first_times.erase(label);
        ss_checkpoint << std::left << std::setw(40) << label << " - " << std::setw(28) << "Time since last checkpoint" << std::setw(9) << diff_checkpoint.count()*1000 << "ms";
        ss_start      << std::left << std::setw(40) << label << " - " << std::setw(28) << "Time since start" << std::setw(9) << diff_start.count()*1000 <<  "ms";
    }
    return std::make_pair(
       ss_checkpoint.str(),
       ss_start.str()
    );
}
#endif

#endif // PRIVMX_ENABLE_LOGGER