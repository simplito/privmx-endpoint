/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/programs/privmxcli/Executer.hpp"
#include "privmx/endpoint/programs/privmxcli/StringArray.hpp"
#include "privmx/endpoint/programs/privmxcli/colors/Colors.hpp"
#include "privmx/endpoint/programs/privmxcli/StringFormater.hpp"
#include <sstream>
#include <fstream>
#include <iomanip>

#include "privmx/utils/PrivmxException.hpp"
#include "privmx/endpoint/core/VarSerializer.hpp"
#include "privmx/endpoint/thread/ThreadVarSerializer.hpp"
#include "privmx/endpoint/store/StoreVarSerializer.hpp"
#include "privmx/endpoint/inbox/InboxVarSerializer.hpp"

using namespace std;
using namespace privmx::endpoint;
using namespace privmx::endpoint::privmxcli;


#define CHECK_ST_ARGS(n) if(st.size() != (n + 1)) {                                                     \
    ERROR_CLI_INVALID_ARG_COUNT()                                                                       \
}                                                                                                       \

#define CHECK_ST_ARGS_2(n1, n2) if(st.size() < (n1 + 1) || st.size() > (n2 + 1)) {                      \
    ERROR_CLI_INVALID_ARG_COUNT()                                                                       \
}

#define ERROR_CLI_INVALID_ARG_COUNT() ERROR_CLI("Invalid args count")

#define ERROR_CLI(ERROR_TEXT)                                                                           \
_console_writer->print_result(Status::Error, chrono::system_clock::now() - _timer_start, ERROR_TEXT );   \
return;                                                                                                 

Executer::Executer(std::thread::id main_thread_id, std::shared_ptr<CliConfig> config, std::shared_ptr<ConsoleWriter> console_writer) : 
    _main_thread_id(main_thread_id), _config(config), _console_writer(console_writer),
    _endpoint(ExecuterEndpoint(_main_thread_id, _config, _console_writer)), _bridge(ExecuterBridge(_main_thread_id, _config, _console_writer)) {}

void Executer::setFA(const std::string &key, const std::string &value){
    func_aliases[key] = value;
}

void Executer::setS(const std::string &key, const Poco::Dynamic::Var &value){
    auto it = session.find(key);
    if(it == session.end()) {
        session[key] = std::make_shared<Poco::Dynamic::Var>(Poco::Dynamic::Var(value));
        return;
    }
    session[key]->operator=(value);
}

void Executer::setSA(const std::string &key, const std::string &key_2){
    session[key] = getS_ptr(key_2);
}

void Executer::copyS(const std::string &key, const std::string &key_2){
    session[key] = std::make_shared<Poco::Dynamic::Var>(getS_var(key_2));
}

func_enum Executer::getFunc(string func_name){
    auto it_a = func_aliases.find(func_name);
    if(it_a != func_aliases.end()){
        func_name = (*it_a).second;
    }
    auto it = functions_internal.find(func_name);
    if(it == functions_internal.end()){
        auto it2 = functions_endpoint.find(use_path+func_name);
        if(it2 != functions_endpoint.end()){
            return (*it2).second;
        }
        auto it3 = functions_bridge.find(use_path+func_name);
        if(it3 != functions_bridge.end()){
            return (*it3).second;
        }
        return nonfunc;
    }
    return (*it).second;
}

std::shared_ptr<Poco::Dynamic::Var> Executer::getS_ptr(const string &key){
    auto it = session.find(key);
    if(it == session.end()){
        return std::make_shared<Poco::Dynamic::Var>(Poco::Dynamic::Var(key));
    }
    return (*it).second;
}

Poco::Dynamic::Var Executer::getS_var(const string &key){
    auto it = session.find(key);
    if(it == session.end()){
        return Poco::Dynamic::Var(key);
    }
    return Poco::Dynamic::Var(*((*it).second));
}

void Executer::addF(const std::string &key, const Poco::Dynamic::Var &value) {
    auto it = session.find(key);
    if(it != session.end()){
        session[key]->operator=(value.convert<std::string>() + (*it).second->convert<std::string>());
        return;
    } else {
        session[key] = std::make_shared<Poco::Dynamic::Var>(value);
        return;
    }
    cout << ConsoleStatusColor::error_critical << key << ": Unknown Data" << endl;
}

void Executer::addB(const std::string &key, const Poco::Dynamic::Var &value) {
    auto it = session.find(key);
    if(it != session.end()){
        session[key]->operator=((*it).second->convert<std::string>() + value.convert<std::string>());
        return;
    } else {
        session[key] = std::make_shared<Poco::Dynamic::Var>(value);
        return;
    }
    cout << ConsoleStatusColor::error_critical << key << ": Unknown Data" << endl;    
}

string Executer::readFileToString(const string& path) {
    ifstream f_stream(path);
    stringstream buf;
    buf << f_stream.rdbuf();
    return buf.str();
}

void Executer::writeFileFromString(const string& content, const string& path) {
    ofstream f_stream(path);
    f_stream << content;
}

void Executer::execute(const Tokens &st) {
    if(st.size() == 0) return;

    std::thread t;
    _timer_start = std::chrono::system_clock::now();
    auto fun_code = getFunc(st[0]);
    switch(fun_code){
        case nonfunc:
            _console_writer->print_info(st[0]);
            _console_writer->print_result(Status::ErrorInvalidInput, chrono::system_clock::now() - _timer_start, "Invalid function name "  + st[0]);
            return;
        case quit:
            exit(EXIT_SUCCESS);
            return;
        case falias:
            {
                _console_writer->print_info("setting function alias");
                CHECK_ST_ARGS(2)
                if(!isValidVarName(st[1])) {
                    _console_writer->print_result(Status::ErrorInvalidInput, chrono::system_clock::now() - _timer_start, "Invalid alias name "  + st[1]);
                    return;
                }
                int tmp = getFunc(st[2]);
                if(tmp == nonfunc){
                    _console_writer->print_result(Status::ErrorInvalidInput, chrono::system_clock::now() - _timer_start, "Invalid function name "  + st[2]);
                    return;
                }
                setFA(st[1], st[2]);
                _console_writer->print_result(Status::Success, chrono::system_clock::now() - _timer_start);
            }
            return;
        case salias:
            _console_writer->print_info("setting variable alias");
            CHECK_ST_ARGS(2)
            if(!isValidVarName(st[1])) {
                _console_writer->print_result(Status::ErrorInvalidInput, chrono::system_clock::now() - _timer_start, "Invalid alias name "  + st[1]);
                return;
            }
            if(!isValidVarName(st[2])) {
                _console_writer->print_result(Status::ErrorInvalidInput, chrono::system_clock::now() - _timer_start, "Invalid var name "  + st[2]);
                
                return;
            }
            setSA(st[1], st[2]);
            _console_writer->print_result(Status::Success, chrono::system_clock::now() - _timer_start);
            return;
        case scopy:
            _console_writer->print_info("copping variable");
            CHECK_ST_ARGS(2);
            if(!isValidVarName(st[1])) {
                _console_writer->print_result(Status::ErrorInvalidInput, chrono::system_clock::now() - _timer_start, "Invalid var name "  + st[1]);
                return;
            }
            if(!isValidVarName(st[2])) {
                _console_writer->print_result(Status::ErrorInvalidInput, chrono::system_clock::now() - _timer_start, "Invalid var name "  + st[2]);
                return;
            }
            copyS(st[1], st[2]);
            _console_writer->print_result(Status::Success, chrono::system_clock::now() - _timer_start);
            return;
        case sset:
            _console_writer->print_info("setting variable");
            CHECK_ST_ARGS(2);
            if(!isValidVarName(st[1])) {
                _console_writer->print_result(Status::ErrorInvalidInput, chrono::system_clock::now() - _timer_start, "Invalid var name "  + st[1]);
                return;
            }
            setS(st[1], st[2]);
            _console_writer->print_result(Status::Success, chrono::system_clock::now() - _timer_start);
            return;
        case sget:
            _console_writer->print_info("getting variable");
            CHECK_ST_ARGS_2(0,1);
            if(st.size() == 1){
                std::ostringstream ss;
                vector<string> vars_names = getAllVars();
                ss << ConsoleStatusColor::info << "Usage: get VAR_NAME" << endl << endl;
                ss << ConsoleStatusColor::info << "Vars: " << endl;
                for(auto var_name : vars_names) {
                    ss << ConsoleStatusColor::normal << var_name << endl;
                }
                _console_writer->print_result(Status::Success, chrono::system_clock::now() - _timer_start, ss.str());
            } else {
                _console_writer->print_result(Status::Success, chrono::system_clock::now() - _timer_start, getS_printable(st[1]));
            }
            return;
        case sreadFile:
            CHECK_ST_ARGS(2);
            {
                _console_writer->print_info("reading file");
                if(!isValidVarName(st[1])) {
                    _console_writer->print_result(Status::ErrorInvalidInput, chrono::system_clock::now() - _timer_start, "Invalid var name "  + st[1]);
                    return;
                }
                string tmp = readFileToString(st[2]);
                setS(st[1], tmp);
                setS(st[1] + "_size", tmp.size());
                _console_writer->print_result(Status::Success, chrono::system_clock::now() - _timer_start);
            }
            return;
        case swriteFile:
            CHECK_ST_ARGS(2);
            {   
                if(!isValidVarName(st[1])) {
                    _console_writer->print_result(Status::ErrorInvalidInput, chrono::system_clock::now() - _timer_start, "Invalid var name "  + st[1]);
                    return;
                }
                auto data = getS_ptr(st[1]);
                if(data->type() == typeid(std::string)) {
                    writeFileFromString(data->convert<std::string>(), st[2]);
                }
                _console_writer->print_result(Status::Success, chrono::system_clock::now() - _timer_start);
            }
            return;
        case a_sleep:
            {
                _console_writer->print_info("sleeping");
                CHECK_ST_ARGS_2(1,2);
                unsigned int T = 0;
                if(st.size() == (2)) {
                    T = sleep_for(std::stoi(st[1]));
                } else if(st.size() == (3)) {
                    T = sleep_for_random(std::stoi(st[1]), std::stoi(st[2]));
                }
                
                std::ostringstream ss;
                ss << ConsoleStatusColor::info << "slept for " << T << "ms";
                _console_writer->print_result(Status::Success, chrono::system_clock::now() - _timer_start, ss.str());
                
            }
            return;
        case addFront:
            _console_writer->print_info("adding to front of variable");
            CHECK_ST_ARGS(2);
            if(!isValidVarName(st[1])) {
                _console_writer->print_result(Status::ErrorInvalidInput, chrono::system_clock::now() - _timer_start, "Invalid var name "  + st[1]);
                return;
            }
            addF(st[1], getS_var(st[2]));
            _console_writer->print_result(Status::Success, chrono::system_clock::now() - _timer_start);
            return;
        case addBack:
            _console_writer->print_info("adding to back of variable");
            CHECK_ST_ARGS(2);
            if(!isValidVarName(st[1])) {
                _console_writer->print_result(Status::ErrorInvalidInput, chrono::system_clock::now() - _timer_start, "Invalid var name "  + st[1]);
                return;
            }
            addB(st[1], getS_var(st[2]));
            _console_writer->print_result(Status::Success, chrono::system_clock::now() - _timer_start);
            return;
        case addFrontString:
            _console_writer->print_info("adding to front of variable");
            CHECK_ST_ARGS(2);
            if(!isValidVarName(st[1])) {
                _console_writer->print_result(Status::ErrorInvalidInput, chrono::system_clock::now() - _timer_start, "Invalid var name "  + st[1]);
                return;
            }
            addF(st[1], st[2]);
            _console_writer->print_result(Status::Success, chrono::system_clock::now() - _timer_start);
            return;
        case addBackString:
            _console_writer->print_info("adding to back of variable");
            CHECK_ST_ARGS(2);
            if(!isValidVarName(st[1])) {
                _console_writer->print_result(Status::ErrorInvalidInput, chrono::system_clock::now() - _timer_start, "Invalid var name "  + st[1]);
                return;
            }
            addB(st[1], st[2]);
            _console_writer->print_result(Status::Success, chrono::system_clock::now() - _timer_start);
            return;
        case help:
            exec_help(st);
            return;
        case use:
            _console_writer->print_info("using");
            CHECK_ST_ARGS_2(0,1);
            if(st.size() == 1) {
                use_path.clear();
            } else {
                use_path = st[1] + ".";
            }
            _console_writer->print_result(Status::Success, chrono::system_clock::now() - _timer_start);
            return;
        default:
            {
                if(fun_code == func_enum::core_waitEvent) {
                    auto t = std::thread([&](func_enum function_code, const Tokens &st){_endpoint.execute(function_code, st);}, fun_code, st);
                    t.detach();
                    return;
                } else if (_endpoint.execute(fun_code, st)) {
                    return;
                } 
                if(_bridge.execute(fun_code, st)) return;
                _console_writer->print_result(Status::Error, chrono::system_clock::now() - _timer_start, "Function execute not found -" + st[0]);
            }
    }
}

void Executer::exec_help(const Tokens &st){
    if(st.size() == 1 || getFunc(st[1]) == help){
        std::ostringstream ss;
        ss << ConsoleStatusColor::help << "Usage: help FUNCTION_NAME" << endl << endl;
        vector<std::string> cli_functions_names;
        for(auto &item : functions_internal){
            cli_functions_names.push_back(item.first);
        }
        sort(cli_functions_names.begin(), cli_functions_names.end());
        ss << ConsoleStatusColor::help << "All Cli Functions: " << endl;
        for(auto &item : cli_functions_names){
            ss << ConsoleStatusColor::info << item << " - " << functions_internal_help_short_description.at(functions_internal.at(item)) << endl;
        }
        // All Endpoint Functions:
        ss << _endpoint.get_all_function_help_printable_string() << endl;
        ss << _bridge.get_all_function_help_printable_string() << endl;


        vector<std::string> functions_aliases;
        for(auto &item : func_aliases){
            functions_aliases.push_back(item.first);
        }
        sort(functions_aliases.begin(), functions_aliases.end());
        ss << ConsoleStatusColor::help << "All Functions Aliases: " << endl;
        for(auto &item : functions_aliases){
            ss << ConsoleStatusColor::info << item << " for " << func_aliases.at(item) << endl;
        }
        ss << endl << endl;
        _console_writer->print_result(Status::Success, chrono::system_clock::now() - _timer_start, ss.str());
        return;
    }
    auto fun_code = getFunc(st[1]);
    if(fun_code == func_enum::nonfunc) {
        _console_writer->print_result(Status::Error, chrono::system_clock::now() - _timer_start, "Invalid function name " + st[1]);
        return;
    }
    auto it_internal = functions_internal_help_description.find(fun_code);
    auto it_internal_short = functions_internal_help_short_description.find(fun_code);
    std::ostringstream ss;
    if(it_internal == functions_internal_help_description.end() && it_internal_short == functions_internal_help_short_description.end()) {
        bool endpoint_function_found = _endpoint.execute_help(fun_code, st[1]);
        if(!endpoint_function_found){
            _console_writer->print_result(Status::Error, chrono::system_clock::now() - _timer_start, "Function description not found " + st[1]);
        }
        return;
    }
    if(it_internal_short == functions_internal_help_short_description.end()) {
        ss << ConsoleStatusColor::warning << st[1] << " - Short description not found" << endl;
    } else {
        ss << ConsoleStatusColor::info << (*it_internal_short).second << endl;
    }
    if(it_internal == functions_internal_help_description.end()) {
        ss << ConsoleStatusColor::warning << st[1] << " - Extended description not found" << endl;
    } else {
        ss << ConsoleStatusColor::help << (*it_internal).second << endl;
    }  
    _console_writer->print_result(Status::Success, chrono::system_clock::now() - _timer_start, ss.str());
}

vector<string> Executer::getAllVars(){
    vector<string> tmp;
    for(auto &item : session){
        tmp.push_back(item.first);
    }
    sort(tmp.begin(), tmp.end());
    return tmp;
}

unsigned int Executer::sleep_for(const int& T) {
    std::this_thread::sleep_for(std::chrono::milliseconds(T));
    return T;
}

unsigned int Executer::sleep_for_random(const int& T1, const int& T2) {
    int random_time = std::rand() / (RAND_MAX / (T2-T1));
    std::this_thread::sleep_for(std::chrono::milliseconds(T1 + random_time));
    return T1 + random_time;
}

bool Executer::isValidVarName(const std::string &key) {
    for(auto c : key) {
        if (c == '\\' || c == '(' || c == ')' || c == '[' || c == ']' || c == '{' || c == '}' || c == '$' || c == '\'' || c == '"') {
            return false;
        }
    }
    return true;
}

bool Executer::isNumber(const std::string &val) {
    return !val.empty() && std::find_if(val.begin(), 
        val.end(), [](unsigned char c) { return !std::isdigit(c); }) == val.end();

}

string Executer::getS_printable(const std::string &key) {
    auto var = getS_ptr(key);
    if(var->type() == typeid(std::string)) {
        std::string val = var->convert<std::string>();
        if(isNumber(val)) {
            switch (_config->get_format) {
                case get_format_type::bash:
                case get_format_type::cpp:
                case get_format_type::python:
                    return key + ": " + val;
                default:
                    return key + " (number): " + val;
            }
        } else {
            std::ostringstream ss;
            switch (_config->get_format) {
                case get_format_type::bash:
                    return key + ": " + val;
                case get_format_type::cpp:
                    StringFormater::toCPP(ss, val);
                    return key + ": " + ss.str();
                case get_format_type::python:
                    StringFormater::toPython(ss, val);
                    return key + ": " + ss.str();
                default:
                    return key + " (string): " + val;
            }
        }

    } else {
        return key + ": Unknown Data";
    }
}