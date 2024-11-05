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



Executer::Executer(std::thread::id main_thread_id, CliConfig config) : _main_thread_id(main_thread_id), _config(config), _loading_animation(LoadingAnimation()) {
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

void Executer::updateCliConfig(CliConfig config) {
    _config = config;
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
    if(_config.stop_on_error) exit(EXIT_FAILURE);
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
    if(_config.stop_on_error) exit(EXIT_FAILURE);
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
    auto fun_code = getFunc(st[0]);
    switch(fun_code){
        case nonfunc:
            executePrePrintInfo(st[0]);
            executePrePrintOutput(true);
            cout << ConsoleStatusColor::error << "Invalid function name "  << st[0] << endl;
            executePostPrint();
            break;
        case quit:
            exit(EXIT_SUCCESS);
            break;
        case falias:
            {
                executePrePrintInfo("setting function alias");
                CHECK_ST_ARGS(2)
                if(!isValidVarName(st[1])) {
                    executePrePrintOutput(true);
                    cout << ConsoleStatusColor::error << "Invalid alias name "  << st[1] << endl;
                    break;
                }
                int tmp = getFunc(st[2]);
                if(tmp == nonfunc){
                    executePrePrintOutput(true);
                    cout << ConsoleStatusColor::error << "Invalid function name "  << st[2] << endl;
                    if(_config.stop_on_error) exit(EXIT_FAILURE);
                    break;
                }
                setFA(st[1], st[2]);
                executePrePrintOutput();
                executePostPrint();
            }
            break;
        case salias:
            executePrePrintInfo("setting variable alias");
            CHECK_ST_ARGS(2)
            if(!isValidVarName(st[1])) {
                executePrePrintOutput(true);
                cout << ConsoleStatusColor::error << "Invalid alias name "  << st[1] << endl;
                break;
            }
            if(!isValidVarName(st[2])) {
                executePrePrintOutput(true);
                cout << ConsoleStatusColor::error << "Invalid var name "  << st[2] << endl;
                break;
            }
            setSA(st[1], st[2]);
            executePrePrintOutput();
            executePostPrint();
            break;
        case scopy:
            executePrePrintInfo("copping variable");
            CHECK_ST_ARGS(2);
            if(!isValidVarName(st[1])) {
                executePrePrintOutput(true);
                cout << ConsoleStatusColor::error << "Invalid var name "  << st[1] << endl;
                break;
            }
            if(!isValidVarName(st[2])) {
                executePrePrintOutput(true);
                cout << ConsoleStatusColor::error << "Invalid var name "  << st[2] << endl;
                break;
            }
            copyS(st[1], st[2]);
            executePrePrintOutput();
            executePostPrint();
            break;
        case sset:
            executePrePrintInfo("setting variable");
            CHECK_ST_ARGS(2);
            if(!isValidVarName(st[1])) {
                executePrePrintOutput(true);
                cout << ConsoleStatusColor::error << "Invalid var name "  << st[1] << endl;
                break;
            }
            setS(st[1], st[2]);
            executePrePrintOutput();
            executePostPrint();
            break;
        // case ssetArray:
            // setS(st[1], StringArray(vector<string>(st.begin() + 2, st.end())));
            // setS(st[1] + "_size", st.size() - 2);
            // break;
        case sget:
            executePrePrintInfo("getting variable");
            CHECK_ST_ARGS_2(0,1);
            if(st.size() == 1){
                executePrePrintOutput();
                cout << ConsoleStatusColor::info << "Usage: get VAR_NAME" << endl << endl;
                cout << ConsoleStatusColor::info << "Vars: " << endl;
                printAllVars();
                cout << ConsoleStatusColor::normal << endl;
            } else {
                getS_print_value(st[1]);
            }
            executePostPrint();
            break;
        case sreadFile:
            CHECK_ST_ARGS(2);
            {
                executePrePrintInfo("reading file");
                if(!isValidVarName(st[1])) {
                    executePrePrintOutput(true);
                    cout << ConsoleStatusColor::error << "Invalid var name "  << st[1] << endl;
                    break;
                }
                string tmp = readFileToString(st[2]);
                setS(st[1], tmp);
                setS(st[1] + "_size", tmp.size());
                executePrePrintOutput();
                executePostPrint();
            }
            break;
        case swriteFile:
            CHECK_ST_ARGS(2);
            {   
                if(!isValidVarName(st[1])) {
                    executePrePrintOutput(true);
                    cout << ConsoleStatusColor::error << "Invalid var name "  << st[1] << endl;
                    break;
                }
                auto data = getS_ptr(st[1]);
                if(data->type() == typeid(std::string)) {
                    writeFileFromString(data->convert<std::string>(), st[2]);
                }
                executePrePrintOutput();
                executePostPrint();
            }
            break;
        case a_sleep:
            {
                executePrePrintInfo("sleeping");
                CHECK_ST_ARGS_2(1,2);
                unsigned int T = 0;
                if(st.size() == (2)) {
                    T = sleep_for(std::stoi(st[1]));
                } else if(st.size() == (3)) {
                    T = sleep_for_random(std::stoi(st[1]), std::stoi(st[2]));
                }
                executePrePrintOutput();
                cout << ConsoleStatusColor::info << "slept for " << T << "ms" << endl;
                executePostPrint();
            }
            break;
        case addFront:
            executePrePrintInfo("adding to front of variable");
            CHECK_ST_ARGS(2);
            if(!isValidVarName(st[1])) {
                executePrePrintOutput(true);
                cout << ConsoleStatusColor::error << "Invalid var name "  << st[1] << endl;
                break;
            }
            addF(st[1], getS_var(st[2]));
            executePrePrintOutput();
            executePostPrint();
            break;
        case addBack:
            executePrePrintInfo("adding to back of variable");
            CHECK_ST_ARGS(2);
            if(!isValidVarName(st[1])) {
                executePrePrintOutput(true);
                cout << ConsoleStatusColor::error << "Invalid var name "  << st[1] << endl;
                break;
            }
            addB(st[1], getS_var(st[2]));
            executePrePrintOutput();
            executePostPrint();
            break;
        case addFrontString:
            executePrePrintInfo("adding to front of variable");
            CHECK_ST_ARGS(2);
            if(!isValidVarName(st[1])) {
                executePrePrintOutput(true);
                cout << ConsoleStatusColor::error << "Invalid var name "  << st[1] << endl;
                break;
            }
            addF(st[1], st[2]);
            executePrePrintOutput();
            executePostPrint();
            break;
        case addBackString:
            executePrePrintInfo("adding to back of variable");
            CHECK_ST_ARGS(2);
            if(!isValidVarName(st[1])) {
                executePrePrintOutput(true);
                cout << ConsoleStatusColor::error << "Invalid var name "  << st[1] << endl;
                break;
            }
            addB(st[1], st[2]);
            executePrePrintOutput();
            executePostPrint();
            break;
        case help:
            exec_help(st);
            break;
        case use:
            executePrePrintInfo("using");
            CHECK_ST_ARGS_2(0,1);
            if(st.size() == 1) {
                use_path.clear();
            } else {
                use_path = st[1] + ".";
            }
            executePrePrintOutput();
            executePostPrint();
            break;  
        default:
            if(st.size() != (2)) {
                executePrePrintInfo("Running " + st[0]);
                executePrePrintOutput(true);
                std::cerr << ConsoleStatusColor::error << "Invalid args count" << std::endl;
                executePostPrint();
                return;
            }
            if(fun_code == func_enum::core_waitEvent) {
                auto t = std::thread([&](func_enum function_code, std::string fun_name, std::string arg){executeApiFunction(function_code, fun_name, arg);}, fun_code, st[0], st[1]);
                t.detach();
            } else {
                executeApiFunction(fun_code, st[0], st[1]);
            }
    }
}

void Executer::executeApiFunction(const func_enum& fun_code, const std::string& fun_name, const std::string& st) {
    auto it = functions_execute.find(fun_code);
    if(it == functions_execute.end()){
        if(this_thread::get_id() == _main_thread_id) {
            executePrePrintInfo("Running " + fun_name);
        } else {
            executePrePrintInfo("Running in thread " + fun_name);
        }
        executePrePrintOutput(true);
        cout << ConsoleStatusColor::error << "no Api function found for - " << fun_name << endl;
        executePostPrint();
        if(_config.stop_on_error) exit(EXIT_FAILURE);
    } else {
        auto it_2 = functions_action_description.find(fun_code);
        if(it_2 == functions_action_description.end()){
            if(this_thread::get_id() == _main_thread_id) {
                executePrePrintInfo("Running "+ fun_name);
            } else {
                executePrePrintInfo("Running in thread "+ fun_name);
            }
        } else {
            if(this_thread::get_id() == _main_thread_id) {
                executePrePrintInfo((*it_2).second);
            } else {
                executePrePrintInfo((*it_2).second + " in thread ");
            }
        }
        std::function<Poco::Dynamic::Var (std::shared_ptr<ApiVar>, const Poco::JSON::Array::Ptr &)> exec = (*it).second;
        Poco::JSON::Object::Ptr result = Poco::JSON::Object::Ptr(new Poco::JSON::Object());
        try {
            auto raw_JSON_arg = st;
            auto evaluated_JSON_arg_var = getS_var(raw_JSON_arg);
            auto evaluated_JSON_arg_string = evaluated_JSON_arg_var.convert<std::string>();
            Poco::JSON::Array::Ptr args = privmx::utils::Utils::parseJson(evaluated_JSON_arg_string).extract<Poco::JSON::Array::Ptr>();
            auto value = exec(_endpoint, args);            
            if(this_thread::get_id() == _main_thread_id) {
                executePrePrintOutput(false);
                if(!value.isEmpty()) {
                    std::cout << privmx::utils::Utils::stringifyVar(value, true) << std::endl;
                } else {
                    std::cout << "null" << std::endl;
                }
                executePostPrint();
            } else {
                executePrePrintOutput(false, fun_name+"-");
                if(!value.isEmpty()) {
                    std::cout << privmx::utils::Utils::stringifyVar(value, true) << std::endl;
                } else {
                    std::cout << "null" << std::endl;
                }
                executePostPrint();
            }
        } catch (const privmx::utils::PrivmxException& e) {
            std::ostringstream ss;
            ss << "0x" << std::setfill('0') << std::setw(8) << std::hex << e.getCode();
            result->set("Error", e.what());
            result->set("ErrorCodeHex", ss.str());
            result->set("ErrorCode", e.getCode());
            result->set("ErrorData", e.getData());
            result->set("ErrorType", "privmx::utils::PrivmxException");
            executePrePrintOutput(true);
            std::cout << ConsoleStatusColor::error << privmx::utils::Utils::stringify(result, true) << std::endl;
            executePostPrint();
            if(_config.stop_on_error) exit(EXIT_FAILURE);
        } catch (const core::Exception& e) {
            std::ostringstream ss;
            ss << "0x" << std::setfill('0') << std::setw(8) << std::hex << e.getCode();
            result->set("ErrorMsg", e.what());
            result->set("ErrorName", e.getName());
            result->set("ErrorScope", e.getScope());
            result->set("ErrorCodeHex", ss.str());
            result->set("ErrorCode", e.getCode());
            result->set("ErrorDescription", e.getDescription());
            result->set("ErrorType", "core::Exception");
            // result->set("ErrorData", e.getData());
            executePrePrintOutput(true);
            std::cout << ConsoleStatusColor::error << privmx::utils::Utils::stringify(result, true) << std::endl;
            executePostPrint();
            if(_config.stop_on_error) exit(EXIT_FAILURE);
        } catch (const std::exception& e) {
            result->set("Error", e.what());
            result->set("Type", "std::exception");
            executePrePrintOutput(true);
            std::cout << ConsoleStatusColor::error << privmx::utils::Utils::stringify(result, true) << std::endl;
            executePostPrint();
            if(_config.stop_on_error) exit(EXIT_FAILURE);
        } catch (...) {
            result->set("Error", "unknown");
            result->set("Type", "unknown");
            executePrePrintOutput(true);
            std::cout << ConsoleStatusColor::error << privmx::utils::Utils::stringify(result, true) << std::endl;
            executePostPrint();
            if(_config.stop_on_error) exit(EXIT_FAILURE);
        }
    }
}

void Executer::exec_help(const Tokens &st){
    if(st.size() == 1 || getFunc(st[1]) == help){
        cout << ConsoleStatusColor::help << "Usage: help FUNCTION_NAME" << endl << endl;
        printAllFunctions();
        cout << ConsoleStatusColor::normal << endl << endl;
        return;
    }
    auto fun_code = getFunc(st[1]);
    if(fun_code == func_enum::nonfunc) {
        cout << ConsoleStatusColor::error << "Invalid function name " << st[1] << endl;
        return;
    }
    auto it_internal = functions_internal_help_description.find(fun_code);
    auto it_internal_short = functions_internal_help_short_description.find(fun_code);
    if(it_internal == functions_internal_help_description.end() && it_internal_short == functions_internal_help_short_description.end()) {
        auto it = functions_help_description.find(fun_code);
        auto it_short = functions_help_short_description.find(fun_code);
        if(it == functions_help_description.end() && it_short == functions_help_short_description.end()){
            cout << ConsoleStatusColor::error << "Function description not found " << st[1] << endl;
            if(_config.stop_on_error) exit(EXIT_FAILURE);
            return;
        }
        if(it_short == functions_help_short_description.end()) {
            cout << ConsoleStatusColor::warning << st[1] << " - Short description not found" << endl;
        } else {
            cout << ConsoleStatusColor::info << (*it_short).second << endl;
        }
        if(it == functions_help_description.end()) {
            cout << ConsoleStatusColor::warning << st[1] << " - Extended description not found" << endl;
        } else {
            cout << ConsoleStatusColor::help << (*it).second << endl;
        }
        return;
    }
    if(it_internal_short == functions_internal_help_short_description.end()) {
        cout << ConsoleStatusColor::warning << st[1] << " - Short description not found" << endl;
    } else {
        cout << ConsoleStatusColor::info << (*it_internal_short).second << endl;
    }
    if(it_internal == functions_internal_help_description.end()) {
        cout << ConsoleStatusColor::warning << st[1] << " - Extended description not found" << endl;
    } else {
        cout << ConsoleStatusColor::help << (*it_internal).second << endl;
    }  
}


void Executer::executePrePrintInfo(const std::string& info_name) {
    if(_config.is_rl_input && this_thread::get_id() != _main_thread_id){
        rl_clear_visible_line();
    }
    if(_config.add_timestamps) {
        _timer_start = std::chrono::system_clock::now();
    }
    cout << ConsoleStatusColor::normal << "-> " << colors::ConsoleColor::blue << info_name << colors::ConsoleColor::reset;
    if (this_thread::get_id() == _main_thread_id) {
        cout << " ... ";
    } else {
        cout << endl;
    }
    if (_config.is_rl_input && this_thread::get_id() == _main_thread_id) {
        _loading_animation.start();
    }
}



void Executer::executePrePrintOutput(bool is_error, const std::string& extra_info){
    if(_config.add_timestamps && this_thread::get_id() == _main_thread_id) {
        _timer_stop = std::chrono::system_clock::now();
    }
    if(_config.is_rl_input && this_thread::get_id() == _main_thread_id){
        _loading_animation.stop();
    }
    executePrePrintOutputStatus(is_error, extra_info);
    executePrePrintOutputResult(is_error, extra_info);
}

void Executer::executePrePrintOutputStatus(bool is_error, const std::string& extra_info) {
    if(this_thread::get_id() == _main_thread_id) {
        if(is_error) {
            cout << ConsoleStatusColor::error << "ERR" << ConsoleStatusColor::normal << " ";;
        } else {
            cout  << ConsoleStatusColor::ok << "OK" << ConsoleStatusColor::normal << " ";;
        }
        if(_config.add_timestamps && this_thread::get_id() == _main_thread_id) {
            printTimestamp(_timer_start, _timer_stop);
        }
        cout << endl;
    }
}


void Executer::executePrePrintOutputResult(bool is_error, const std::string& extra_info) {
    if(this_thread::get_id() != _main_thread_id) {
        cout << endl;
    }
    if(is_error) {
        cout << ConsoleStatusColor::normal << "-> " << ConsoleStatusColor::error << extra_info << "RESULT" << ConsoleStatusColor::normal << ":" << endl;
    } else {
        cout << ConsoleStatusColor::normal << "-> " << ConsoleStatusColor::ok << extra_info << "RESULT" << ConsoleStatusColor::normal << ":" << endl;
    }
}




void Executer::executePostPrint(){
    if(_config.is_rl_input && this_thread::get_id() != _main_thread_id){
        rl_on_new_line();
        rl_redisplay();
    }

}

void Executer::printAllFunctions(){
    vector<std::string> tmp;
    for(auto &item : functions_internal){
        tmp.push_back(item.first);
    }
    sort(tmp.begin(), tmp.end());
    cout << ConsoleStatusColor::help << "All Cli Functions: " << endl;
    for(auto &item : tmp){
        cout << ConsoleStatusColor::info << item << " - " << functions_internal_help_short_description.at(functions_internal.at(item)) << endl;
    }

    tmp.clear();
    for(auto &item : functions){
        tmp.push_back(item.first);
    }
    sort(tmp.begin(), tmp.end());
    cout << ConsoleStatusColor::help << "All Api Functions: " << endl;
    for(auto &item : tmp){
        cout << ConsoleStatusColor::info << item << " - " << functions_help_short_description.at(functions.at(item)) << endl;
    }

    tmp.clear();
    for(auto &item : func_aliases){
        tmp.push_back(item.first);
    }
    sort(tmp.begin(), tmp.end());
    cout << ConsoleStatusColor::help << "All Functions Aliases: " << endl;
    for(auto &item : tmp){
        cout << ConsoleStatusColor::info << item << " for " << func_aliases.at(item) << endl;
    }
}

void Executer::printAllVars(){
    vector<string> tmp;

    for(auto &item : session){
        tmp.push_back(item.first);
    }

    sort(tmp.begin(), tmp.end());

    for(auto &item : tmp){
        cout << ConsoleStatusColor::info << item << "\t";
    }
}

void Executer::printTimestamp(std::chrono::_V2::system_clock::time_point start, std::chrono::_V2::system_clock::time_point stop) {
    if (_config.add_timestamps) {
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

void Executer::getS_print_value(const std::string &key) {
    executePrePrintOutput();
    auto var = getS_ptr(key);
    if(var->type() == typeid(std::string)) {
        std::string val = var->convert<std::string>();

        if(isNumber(val)) {
            switch (_config.get_format) {
                case get_format_type::bash:
                    std::cout << ConsoleStatusColor::normal << key << ": " << val << std::endl;
                    break;
                case get_format_type::cpp:
                    std::cout << ConsoleStatusColor::normal << key << ": " << val << std::endl;
                    break;
                case get_format_type::python:
                    std::cout << ConsoleStatusColor::normal << key << ": " << val << std::endl;
                    break;
                default:
                    std::cout << ConsoleStatusColor::normal << key << " (number): " << val << std::endl;
                    break;
            }
        } else {
            switch (_config.get_format) {
                case get_format_type::bash:
                    std::cout << ConsoleStatusColor::normal << key << ": " << val << std::endl;
                    break;
                case get_format_type::cpp:
                    std::cout << ConsoleStatusColor::normal << key << ": ";
                    StringFormater::toCPP(std::cout, val);
                    std::cout << std::endl;
                    break;
                case get_format_type::python:
                    std::cout << ConsoleStatusColor::normal << key << ": ";
                    StringFormater::toPython(std::cout, val);
                    std::cout << std::endl;
                    break;
                default:
                    std::cout << ConsoleStatusColor::normal << key << " (string): " << val << std::endl;
                    break;
            }
        }

    } else {
        executePrePrintOutput(true);
        cout << ConsoleStatusColor::error << key << ": Unknown Data" << endl;
    }
}