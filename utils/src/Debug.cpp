
#include <privmx/utils/Debug.hpp>

#ifdef PRIVMX_USE_DEBUG

using namespace std;
using namespace privmx;
using namespace privmx::utils;
using namespace privmx::utils::debug;


void Debug::print(const std::string& msg, const std::string& label, const std::string& group_name) {
    PRIVMX_DEBUG_OUTPUT(group_name + ":" + label, msg)
}
void Debug::print(const std::string& msg, const std::string& label) {
    PRIVMX_DEBUG_OUTPUT("DEBUG:" + label, msg)
}
void Debug::print(const std::string& msg) {
    PRIVMX_DEBUG_OUTPUT("DEBUG:UNKNOWN", msg)
}
void Debug::print(const int64_t& msg, const std::string& label, const std::string& group_name) {
    PRIVMX_DEBUG_OUTPUT(group_name + ":" + label, msg)
}
void Debug::print(const int64_t& msg, const std::string& label) {
    PRIVMX_DEBUG_OUTPUT("DEBUG:" + label, msg)
}
void Debug::print(const int64_t& msg) {
    PRIVMX_DEBUG_OUTPUT("DEBUG:UNKNOWN", msg)
}

#ifdef PRIVMX_DEBUG_TIME
shared_ptr<DebugTimer> DebugTimer::_instance;
mutex DebugTimer::_instance_mutex;

shared_ptr<DebugTimer> DebugTimer::getInstance() {
    lock_guard<mutex> lock(_instance_mutex);
    if (_instance == nullptr) {
        _instance =  std::make_shared<DebugTimer>();
    }
    return _instance;
}

DebugTimer::DebugTimer(const std::string& group_and_test_label) {
    _first_times[group_and_test_label] = chrono::system_clock::now();
    _last_times[group_and_test_label] = chrono::system_clock::now();
    PRIVMX_DEBUG_OUTPUT(group_and_test_label,"Initialized at              ",chrono::system_clock::to_time_t(_first_times["main:DebugTimer"]))
}

void DebugTimer::start(const std::string& group_name, const std::string& test_label, const std::string& msg) {
    start_internal(group_name+":"+test_label, msg);
}
void DebugTimer::start(const std::string& test_label) {
    start_internal("main:"+test_label);
}
void DebugTimer::checkpoint(const std::string& group_name, const std::string& test_label, const std::string& msg) {
    checkpoint_internal(group_name+":"+test_label, msg);
}
void DebugTimer::checkpoint(const std::string& test_label) {
    checkpoint_internal("main:"+test_label);
}
void DebugTimer::stop(const std::string& group_name, const std::string& test_label, const std::string& msg) {
    stop_internal(group_name+":"+test_label, msg);
}
void DebugTimer::stop(const std::string& test_label) {
    stop_internal("main:"+test_label);
}


void DebugTimer::start_internal(const string& group_and_test_label, const std::string& msg) {
    std::string output_msg = "";
    if(msg != "") output_msg = " - " + msg;
    if(chrono::system_clock::to_time_t(_first_times[group_and_test_label]) != 0) {
        PRIVMX_DEBUG_OUTPUT(group_and_test_label, "Group and test label is used reseting data")
    }
    _first_times[group_and_test_label] = chrono::system_clock::now();
    _last_times[group_and_test_label] = chrono::system_clock::now();
    #ifdef PRIVMX_DEBUG_OUTPUT_TIMESTAMP_ON_START
        PRIVMX_DEBUG_OUTPUT(group_and_test_label,"Started at",chrono::system_clock::to_time_t(_first_times[group_and_test_label]), output_msg)
    #endif
}

void DebugTimer::checkpoint_internal(const string& group_and_test_label, const std::string& msg) {
    std::string output_msg = "";
    if(msg != "") output_msg = " - " + msg;
    if(chrono::system_clock::to_time_t(_first_times[group_and_test_label]) == 0) {
        PRIVMX_DEBUG_OUTPUT(group_and_test_label,"Group and test label not initialized")
        return;
    }
    auto current_time = chrono::system_clock::now();
    const chrono::duration<double> diff = current_time - _last_times[group_and_test_label];
    #ifdef PRIVMX_DEBUG_OUTPUT_TIMESTAMP_ON_CHECKPOINT 
        PRIVMX_DEBUG_OUTPUT(group_and_test_label,"Checkpoint at",chrono::system_clock::to_time_t(_first_times[group_and_test_label]), output_msg)
    #endif
    PRIVMX_DEBUG_OUTPUT(group_and_test_label,"Time since last checkpoint",to_string(diff.count()*1000)+" ms", output_msg);
    _last_times[group_and_test_label] = current_time;
}

void DebugTimer::stop_internal(const string& group_and_test_label, const std::string& msg) {
    std::string output_msg = "";
    if(msg != "") output_msg = " - " + msg;
    if(chrono::system_clock::to_time_t(_first_times[group_and_test_label]) == 0) {
        PRIVMX_DEBUG_OUTPUT(group_and_test_label,"Group and test label not initialized")
        return;
    }
    auto current_time = chrono::system_clock::now();
    const chrono::duration<double> diff = current_time - _last_times[group_and_test_label];
    const chrono::duration<double> diff2 = current_time - _first_times[group_and_test_label];
    #ifdef PRIVMX_DEBUG_OUTPUT_TIMESTAMP_ON_STOP
        PRIVMX_DEBUG_OUTPUT(group_and_test_label,"Stoped at",chrono::system_clock::to_time_t(_first_times[group_and_test_label]), output_msg)
    #endif
    PRIVMX_DEBUG_OUTPUT(group_and_test_label,"Time since last checkpoint",to_string(diff.count()*1000)+" ms", output_msg)
    PRIVMX_DEBUG_OUTPUT(group_and_test_label,"Time since start",to_string(diff2.count()*1000)+" ms", output_msg)

    _last_times.erase(group_and_test_label);
    _first_times.erase(group_and_test_label);
}
#endif // PRIVMX_DEBUG_TIME


#endif //PRIVMX_USE_DEBUG