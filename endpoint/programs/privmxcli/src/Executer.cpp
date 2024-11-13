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
#include <iomanip>


#include "privmx/endpoint/core/VarSerializer.hpp"
#include "privmx/endpoint/thread/ThreadVarSerializer.hpp"
#include "privmx/endpoint/store/StoreVarSerializer.hpp"
#include "privmx/endpoint/inbox/InboxVarSerializer.hpp"

using namespace std;
using namespace privmx::endpoint;
using namespace privmx::endpoint::privmxcli;



Executer::Executer(std::thread::id main_thread_id, std::shared_ptr<CliConfig> config) : _main_thread_id(main_thread_id), _config(config), _console_writer(ConsoleWriter(main_thread_id, config)), _loading_animation(LoadingAnimation()) {
    core::VarSerializer serializer = core::VarSerializer(core::VarSerializer::Options{.addType = true, .binaryFormat = core::VarSerializer::Options::STD_STRING_AS_BASE64});
    core::EventQueueVarInterface event = core::EventQueueVarInterface(core::EventQueue::getInstance(), serializer);
    core::ConnectionVarInterface connection = core::ConnectionVarInterface(serializer);
    core::BackendRequesterVarInterface backendRequester = core::BackendRequesterVarInterface(serializer);
    crypto::CryptoApiVarInterface crypto = crypto::CryptoApiVarInterface(serializer);
    thread::ThreadApiVarInterface thread = thread::ThreadApiVarInterface(connection.getApi(),serializer);
    store::StoreApiVarInterface store = store::StoreApiVarInterface(connection.getApi(),serializer);
    inbox::InboxApiVarInterface inbox = inbox::InboxApiVarInterface(connection.getApi(),thread.getApi(), store.getApi(),serializer);
    _endpoint = std::make_shared<ApiVar>(event, connection, backendRequester, crypto, thread, store, inbox);
}

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
        auto it2 = functions.find(use_path+func_name);
        if(it2 == functions.end()){
            return nonfunc;
        }
        return (*it2).second;
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

void Executer::set_bridge_api_creds(const std::string &bridge_api_key_id, const std::string &bridge_api_key_secret, const std::string &bridge_url) {
    _bridge_api_key_id = bridge_api_key_id;
    _bridge_api_key_secret = bridge_api_key_secret;
    _bridge_url = bridge_url;
}

void Executer::execute(const Tokens &st) {
    if(st.size() == 0) return;

    std::thread t;
    _timer_start = std::chrono::system_clock::now();
    auto fun_code = getFunc(st[0]);
    switch(fun_code){
        case nonfunc:
            _console_writer.print_info(st[0]);
            _console_writer.print_result(Status::ErrorInvalidInput, chrono::system_clock::now() - _timer_start, "Invalid function name "  + st[0]);
            break;
        case quit:
            exit(EXIT_SUCCESS);
            break;
        case falias:
            {
                _console_writer.print_info("setting function alias");
                CHECK_ST_ARGS(2)
                if(!isValidVarName(st[1])) {
                    _console_writer.print_result(Status::ErrorInvalidInput, chrono::system_clock::now() - _timer_start, "Invalid alias name "  + st[1]);
                    break;
                }
                int tmp = getFunc(st[2]);
                if(tmp == nonfunc){
                    _console_writer.print_result(Status::ErrorInvalidInput, chrono::system_clock::now() - _timer_start, "Invalid function name "  + st[2]);
                    break;
                }
                setFA(st[1], st[2]);
                _console_writer.print_result(Status::Success, chrono::system_clock::now() - _timer_start);
            }
            break;
        case salias:
            _console_writer.print_info("setting variable alias");
            CHECK_ST_ARGS(2)
            if(!isValidVarName(st[1])) {
                _console_writer.print_result(Status::ErrorInvalidInput, chrono::system_clock::now() - _timer_start, "Invalid alias name "  + st[1]);
                break;
            }
            if(!isValidVarName(st[2])) {
                _console_writer.print_result(Status::ErrorInvalidInput, chrono::system_clock::now() - _timer_start, "Invalid var name "  + st[2]);
                
                break;
            }
            setSA(st[1], st[2]);
            _console_writer.print_result(Status::Success, chrono::system_clock::now() - _timer_start);
            break;
        case scopy:
            _console_writer.print_info("copping variable");
            CHECK_ST_ARGS(2);
            if(!isValidVarName(st[1])) {
                _console_writer.print_result(Status::ErrorInvalidInput, chrono::system_clock::now() - _timer_start, "Invalid var name "  + st[1]);
                break;
            }
            if(!isValidVarName(st[2])) {
                _console_writer.print_result(Status::ErrorInvalidInput, chrono::system_clock::now() - _timer_start, "Invalid var name "  + st[2]);
                break;
            }
            copyS(st[1], st[2]);
            _console_writer.print_result(Status::Success, chrono::system_clock::now() - _timer_start);
            break;
        case sset:
            _console_writer.print_info("setting variable");
            CHECK_ST_ARGS(2);
            if(!isValidVarName(st[1])) {
                _console_writer.print_result(Status::ErrorInvalidInput, chrono::system_clock::now() - _timer_start, "Invalid var name "  + st[1]);
                break;
            }
            setS(st[1], st[2]);
            _console_writer.print_result(Status::Success, chrono::system_clock::now() - _timer_start);
            break;
        case sget:
            _console_writer.print_info("getting variable");
            CHECK_ST_ARGS_2(0,1);
            if(st.size() == 1){
                std::ostringstream ss;
                vector<string> vars_names = getAllVars();
                ss << ConsoleStatusColor::info << "Usage: get VAR_NAME" << endl << endl;
                ss << ConsoleStatusColor::info << "Vars: " << endl;
                for(auto var_name : vars_names) {
                    ss << ConsoleStatusColor::normal << var_name << endl;
                }
                _console_writer.print_result(Status::Success, chrono::system_clock::now() - _timer_start, ss.str());
            } else {
                _console_writer.print_result(Status::Success, chrono::system_clock::now() - _timer_start, getS_printable(st[1]));
            }
            break;
        case sreadFile:
            CHECK_ST_ARGS(2);
            {
                _console_writer.print_info("reading file");
                if(!isValidVarName(st[1])) {
                    _console_writer.print_result(Status::ErrorInvalidInput, chrono::system_clock::now() - _timer_start, "Invalid var name "  + st[1]);
                    break;
                }
                string tmp = readFileToString(st[2]);
                setS(st[1], tmp);
                setS(st[1] + "_size", tmp.size());
                _console_writer.print_result(Status::Success, chrono::system_clock::now() - _timer_start);
            }
            break;
        case swriteFile:
            CHECK_ST_ARGS(2);
            {   
                if(!isValidVarName(st[1])) {
                    _console_writer.print_result(Status::ErrorInvalidInput, chrono::system_clock::now() - _timer_start, "Invalid var name "  + st[1]);
                    break;
                }
                auto data = getS_ptr(st[1]);
                if(data->type() == typeid(std::string)) {
                    writeFileFromString(data->convert<std::string>(), st[2]);
                }
                _console_writer.print_result(Status::Success, chrono::system_clock::now() - _timer_start);
            }
            break;
        case a_sleep:
            {
                _console_writer.print_info("sleeping");
                CHECK_ST_ARGS_2(1,2);
                unsigned int T = 0;
                if(st.size() == (2)) {
                    T = sleep_for(std::stoi(st[1]));
                } else if(st.size() == (3)) {
                    T = sleep_for_random(std::stoi(st[1]), std::stoi(st[2]));
                }
                
                std::ostringstream ss;
                ss << ConsoleStatusColor::info << "slept for " << T << "ms";
                _console_writer.print_result(Status::Success, chrono::system_clock::now() - _timer_start, ss.str());
                
            }
            break;
        case addFront:
            _console_writer.print_info("adding to front of variable");
            CHECK_ST_ARGS(2);
            if(!isValidVarName(st[1])) {
                _console_writer.print_result(Status::ErrorInvalidInput, chrono::system_clock::now() - _timer_start, "Invalid var name "  + st[1]);
                break;
            }
            addF(st[1], getS_var(st[2]));
            _console_writer.print_result(Status::Success, chrono::system_clock::now() - _timer_start);
            break;
        case addBack:
            _console_writer.print_info("adding to back of variable");
            CHECK_ST_ARGS(2);
            if(!isValidVarName(st[1])) {
                _console_writer.print_result(Status::ErrorInvalidInput, chrono::system_clock::now() - _timer_start, "Invalid var name "  + st[1]);
                break;
            }
            addB(st[1], getS_var(st[2]));
            _console_writer.print_result(Status::Success, chrono::system_clock::now() - _timer_start);
            break;
        case addFrontString:
            _console_writer.print_info("adding to front of variable");
            CHECK_ST_ARGS(2);
            if(!isValidVarName(st[1])) {
                _console_writer.print_result(Status::ErrorInvalidInput, chrono::system_clock::now() - _timer_start, "Invalid var name "  + st[1]);
                break;
            }
            addF(st[1], st[2]);
            _console_writer.print_result(Status::Success, chrono::system_clock::now() - _timer_start);
            break;
        case addBackString:
            _console_writer.print_info("adding to back of variable");
            CHECK_ST_ARGS(2);
            if(!isValidVarName(st[1])) {
                _console_writer.print_result(Status::ErrorInvalidInput, chrono::system_clock::now() - _timer_start, "Invalid var name "  + st[1]);
                break;
            }
            addB(st[1], st[2]);
            _console_writer.print_result(Status::Success, chrono::system_clock::now() - _timer_start);
            break;
        case help:
            exec_help(st);
            break;
        case use:
            _console_writer.print_info("using");
            CHECK_ST_ARGS_2(0,1);
            if(st.size() == 1) {
                use_path.clear();
            } else {
                use_path = st[1] + ".";
            }
            _console_writer.print_result(Status::Success, chrono::system_clock::now() - _timer_start);
            break;  
        case bridge_setBridgeApiCreds:
            _console_writer.print_info("setting bridge api credentials");
            CHECK_ST_ARGS(3);
            set_bridge_api_creds(st[1], st[2], st[3]);
            _console_writer.print_result(Status::Success, chrono::system_clock::now() - _timer_start);
            break;
        default:
            {
                bool fun_found = false;
                if(fun_code == func_enum::core_waitEvent) {
                    auto t = std::thread([&](func_enum function_code, const Tokens &st){executeApiFunction(function_code, st);}, fun_code, st);
                    t.detach();
                    fun_found = true;
                } else {
                    fun_found = executeApiFunction(fun_code, st);
                }

                if(!fun_found) {
                    _console_writer.print_result(Status::Error, chrono::system_clock::now() - _timer_start, "Function execute not found -" + st[0]);
                }
            }
    }
}

bool Executer::executeApiFunction(const func_enum& fun_code, const Tokens &st) {
    const std::string fun_name = st[0];
    auto it = functions_execute.find(fun_code);
    if(it != functions_execute.end()) {
        auto it_2 = functions_action_description.find(fun_code);
        if(it_2 == functions_action_description.end()){
            if(this_thread::get_id() == _main_thread_id) {
                _console_writer.print_info("Running "+ fun_name);
            } else {
                _console_writer.print_info("Running in thread "+ fun_name);
            }
        } else {
            if(this_thread::get_id() == _main_thread_id) {
                _console_writer.print_info((*it_2).second);
            } else {
                _console_writer.print_info((*it_2).second + " in thread ");
            }
        }
        std::function<Poco::Dynamic::Var (std::shared_ptr<ApiVar>, const Poco::JSON::Array::Ptr &)> exec = (*it).second;
        Poco::JSON::Object::Ptr result = Poco::JSON::Object::Ptr(new Poco::JSON::Object());
        _timer_start = std::chrono::system_clock::now();
        try {
            if(st.size() != (1 + 1)) {
                _console_writer.print_result(Status::ErrorInvalidInput, chrono::system_clock::now() - _timer_start, "Invalid args count" );
                return true; 
            }
            auto raw_JSON_arg = st[1];
            auto evaluated_JSON_arg_var = getS_var(raw_JSON_arg);
            auto evaluated_JSON_arg_string = evaluated_JSON_arg_var.convert<std::string>();
            Poco::JSON::Array::Ptr args = privmx::utils::Utils::parseJson(evaluated_JSON_arg_string).extract<Poco::JSON::Array::Ptr>();
            auto value = exec(_endpoint, args);    
            std::chrono::duration<double> time = chrono::system_clock::now() - _timer_start;
            std::string output = "null";
            if(!value.isEmpty()) {
                output = privmx::utils::Utils::stringifyVar(value, true);
            }
            _console_writer.print_result(Status::Success, time, output, this_thread::get_id() != _main_thread_id ? fun_name+"-": std::string());
        } catch (const privmx::utils::PrivmxException& e) {
            std::chrono::duration<double> time = chrono::system_clock::now() - _timer_start;
            std::ostringstream ss;
            ss << "0x" << std::setfill('0') << std::setw(8) << std::hex << e.getCode();
            result->set("Error", e.what());
            result->set("ErrorCodeHex", ss.str());
            result->set("ErrorCode", e.getCode());
            result->set("ErrorData", e.getData());
            result->set("ErrorType", "privmx::utils::PrivmxException");
            _console_writer.print_result(Status::Success, time, privmx::utils::Utils::stringify(result, true), this_thread::get_id() != _main_thread_id ? fun_name+"-": std::string());
        } catch (const core::Exception& e) {
            std::chrono::duration<double> time = chrono::system_clock::now() - _timer_start;
            std::ostringstream ss;
            ss << "0x" << std::setfill('0') << std::setw(8) << std::hex << e.getCode();
            result->set("ErrorMsg", e.what());
            result->set("ErrorName", e.getName());
            result->set("ErrorScope", e.getScope());
            result->set("ErrorCodeHex", ss.str());
            result->set("ErrorCode", e.getCode());
            result->set("ErrorDescription", e.getDescription());
            result->set("ErrorType", "core::Exception");
            _console_writer.print_result(Status::Success, time, privmx::utils::Utils::stringify(result, true), this_thread::get_id() != _main_thread_id ? fun_name+"-": std::string());
        } catch (const std::exception& e) {
            std::chrono::duration<double> time = chrono::system_clock::now() - _timer_start;
            result->set("Error", e.what());
            result->set("Type", "std::exception");
            _console_writer.print_result(Status::Success, time, privmx::utils::Utils::stringify(result, true), this_thread::get_id() != _main_thread_id ? fun_name+"-": std::string());
        } catch (...) {
            std::chrono::duration<double> time = chrono::system_clock::now() - _timer_start;
            result->set("Error", "unknown");
            result->set("Type", "unknown");
            _console_writer.print_result(Status::Success, time, privmx::utils::Utils::stringify(result, true), this_thread::get_id() != _main_thread_id ? fun_name+"-": std::string());
        }
        return true;
    }
    return false;
}

void Executer::exec_help(const Tokens &st){
    if(st.size() == 1 || getFunc(st[1]) == help){
        std::ostringstream ss;
        ss << ConsoleStatusColor::help << "Usage: help FUNCTION_NAME" << endl << endl;
        vector<std::string> tmp;
        for(auto &item : functions_internal){
            tmp.push_back(item.first);
        }
        sort(tmp.begin(), tmp.end());
        ss << ConsoleStatusColor::help << "All Cli Functions: " << endl;
        for(auto &item : tmp){
            ss << ConsoleStatusColor::info << item << " - " << functions_internal_help_short_description.at(functions_internal.at(item)) << endl;
        }
        tmp.clear();
        for(auto &item : functions){
            tmp.push_back(item.first);
        }
        sort(tmp.begin(), tmp.end());
        ss << ConsoleStatusColor::help << "All Api Functions: " << endl;
        for(auto &item : tmp){
            ss << ConsoleStatusColor::info << item << " - " << functions_help_short_description.at(functions.at(item)) << endl;
        }
        tmp.clear();
        for(auto &item : func_aliases){
            tmp.push_back(item.first);
        }
        sort(tmp.begin(), tmp.end());
        ss << ConsoleStatusColor::help << "All Functions Aliases: " << endl;
        for(auto &item : tmp){
            ss << ConsoleStatusColor::info << item << " for " << func_aliases.at(item) << endl;
        }
        ss << endl << endl;
        _console_writer.print_result(Status::Success, chrono::system_clock::now() - _timer_start, ss.str());
        return;
    }
    auto fun_code = getFunc(st[1]);
    if(fun_code == func_enum::nonfunc) {
        _console_writer.print_result(Status::Error, chrono::system_clock::now() - _timer_start, "Invalid function name " + st[1]);
        return;
    }
    auto it_internal = functions_internal_help_description.find(fun_code);
    auto it_internal_short = functions_internal_help_short_description.find(fun_code);
    std::ostringstream ss;
    if(it_internal == functions_internal_help_description.end() && it_internal_short == functions_internal_help_short_description.end()) {
        auto it = functions_help_description.find(fun_code);
        auto it_short = functions_help_short_description.find(fun_code);
        if(it == functions_help_description.end() && it_short == functions_help_short_description.end()){
            _console_writer.print_result(Status::Error, chrono::system_clock::now() - _timer_start, "Function description not found " + st[1]);
            return;
        }
        if(it_short == functions_help_short_description.end()) {
            ss << ConsoleStatusColor::warning << st[1] << " - Short description not found" << endl;
        } else {
            ss << ConsoleStatusColor::info << (*it_short).second << endl;
        }
        if(it == functions_help_description.end()) {
            ss << ConsoleStatusColor::warning << st[1] << " - Extended description not found" << endl;
        } else {
            ss << ConsoleStatusColor::help << (*it).second << endl;
        }
        _console_writer.print_result(Status::Success, chrono::system_clock::now() - _timer_start, ss.str());
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
    _console_writer.print_result(Status::Success, chrono::system_clock::now() - _timer_start, ss.str());
}

vector<string> Executer::getAllVars(){
    vector<string> tmp;
    for(auto &item : session){
        tmp.push_back(item.first);
    }
    sort(tmp.begin(), tmp.end());
    return tmp;
}

void Executer::printTimestamp(std::chrono::_V2::system_clock::time_point start, std::chrono::_V2::system_clock::time_point stop) {
    if (_config->add_timestamps) {
        chrono::duration<double> diff(stop - start);
        std::cout << ConsoleStatusColor::info << to_string(diff.count()*1000) << "ms" << ConsoleStatusColor::normal;
    }
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