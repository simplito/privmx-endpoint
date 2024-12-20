/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/
#include <sstream>
#include <fstream>
#include <iomanip>

#include "privmx/endpoint/programs/privmxcli/ExecuterBridge.hpp"
#include "privmx/endpoint/programs/privmxcli/colors/Colors.hpp"

#include "privmx/utils/PrivmxException.hpp"
#include "privmx/endpoint/core/VarSerializer.hpp"
#include "privmx/endpoint/thread/ThreadVarSerializer.hpp"
#include "privmx/endpoint/store/StoreVarSerializer.hpp"
#include "privmx/endpoint/inbox/InboxVarSerializer.hpp"

using namespace std;
using namespace privmx::endpoint;
using namespace privmx::endpoint::privmxcli;

ExecuterBridge::ExecuterBridge(std::thread::id main_thread_id, std::shared_ptr<CliConfig> config, std::shared_ptr<ConsoleWriter> console_writer) : 
    _main_thread_id(main_thread_id), _config(config), _console_writer(console_writer) 
{
    core::VarSerializer serializer = core::VarSerializer(core::VarSerializer::Options{.addType = true, .binaryFormat = core::VarSerializer::Options::STD_STRING_AS_BASE64});
    _bridge = std::make_shared<core::BackendRequesterVarInterface>(serializer);
}
bool ExecuterBridge::execute(const func_enum& fun_code, const Tokens &st) {
    _timer_start = std::chrono::system_clock::now();
    std::chrono::duration<double> time = chrono::system_clock::now() - _timer_start;
    const std::string fun_name = st[0];
    if(fun_code == func_enum::bridge_setBridgeApiCreds) {
        _console_writer->print_info("setting bridge api credentials");
        if(st.size() != (3 + 1)) { 
            _console_writer->print_result(Status::Error, chrono::system_clock::now() - _timer_start, "Invalid args count" ); 
            return true; 
        }
        set_api_creds(st[1], st[2], st[3]);
        _console_writer->print_result(Status::Success, chrono::system_clock::now() - _timer_start);
        return true;
    }
    auto it = functions_bridge_execute.find(fun_code);
    if(it != functions_bridge_execute.end()) {
        auto it_2 = functions_bridge_action_description.find(fun_code);
        if(it_2 == functions_bridge_action_description.end()){
            if(this_thread::get_id() == _main_thread_id) {
                _console_writer->print_info("Running "+ fun_name);
            } else {
                _console_writer->print_info("Running in thread "+ fun_name);
            }
        } else {
            if(this_thread::get_id() == _main_thread_id) {
                _console_writer->print_info((*it_2).second);
            } else {
                _console_writer->print_info((*it_2).second + " in thread ");
            }
        }
        if(!_api_key_id.has_value() || !_api_key_secret.has_value() || !_url.has_value()) {
            _console_writer->print_result(Status::ErrorInvalidInput, chrono::system_clock::now() - _timer_start, "Bridge creads not set" );
            return true;
        }
        std::function<Poco::Dynamic::Var (std::shared_ptr<privmx::endpoint::core::BackendRequesterVarInterface>, const std::string&, const std::string&, const std::string&, const std::string&)> exec = (*it).second;
        Poco::JSON::Object::Ptr result = Poco::JSON::Object::Ptr(new Poco::JSON::Object());
        _timer_start = std::chrono::system_clock::now();
        try {
            if(st.size() != (1 + 1)) {
                _console_writer->print_result(Status::ErrorInvalidInput, chrono::system_clock::now() - _timer_start, "Invalid args count" );
                return true; 
            }
            auto raw_JSON_object = st[1];
            auto evaluated_JSON_object = getS_var(raw_JSON_object);
            auto evaluated_JSON_object_string = evaluated_JSON_object.convert<std::string>();
            
            auto value = exec(_bridge, evaluated_JSON_object_string, _api_key_id.value(), _api_key_secret.value(), _url.value());    
            std::chrono::duration<double> time = chrono::system_clock::now() - _timer_start;
            Status exec_status = Status::Success;
            std::string output = "null";
            if(!value.isEmpty()) {
                Poco::JSON::Object::Ptr output_JSON = privmx::utils::Utils::parseJsonObject(value.extract<std::string>());
                if(output_JSON->has("result")) {
                    exec_status = Status::Success;
                    output = privmx::utils::Utils::stringifyVar(output_JSON->get("result"), true);
                } else if (output_JSON->has("error")) {
                    exec_status = Status::Error;
                    output = privmx::utils::Utils::stringifyVar(output_JSON->get("error"), true);
                } else {
                    exec_status = Status::Error;
                    output = privmx::utils::Utils::stringifyVar(output_JSON, true);
                }
            }
            _console_writer->print_result(exec_status, time, output, this_thread::get_id() != _main_thread_id ? fun_name+"-": std::string());
        } catch (const privmx::utils::PrivmxException& e) {
            std::chrono::duration<double> time = chrono::system_clock::now() - _timer_start;
            std::ostringstream ss;
            ss << "0x" << std::setfill('0') << std::setw(8) << std::hex << e.getCode();
            result->set("Error", e.what());
            result->set("ErrorCodeHex", ss.str());
            result->set("ErrorCode", e.getCode());
            result->set("ErrorData", e.getData());
            result->set("ErrorType", "privmx::utils::PrivmxException");
            _console_writer->print_result(Status::Error, time, privmx::utils::Utils::stringify(result, true), this_thread::get_id() != _main_thread_id ? fun_name+"-": std::string());
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
            _console_writer->print_result(Status::Error, time, privmx::utils::Utils::stringify(result, true), this_thread::get_id() != _main_thread_id ? fun_name+"-": std::string());
        } catch (const std::exception& e) {
            std::chrono::duration<double> time = chrono::system_clock::now() - _timer_start;
            result->set("Error", e.what());
            result->set("Type", "std::exception");
            _console_writer->print_result(Status::Error, time, privmx::utils::Utils::stringify(result, true), this_thread::get_id() != _main_thread_id ? fun_name+"-": std::string());
        } catch (...) {
            std::chrono::duration<double> time = chrono::system_clock::now() - _timer_start;
            result->set("Error", "unknown");
            result->set("Type", "unknown");
            _console_writer->print_result(Status::Error, time, privmx::utils::Utils::stringify(result, true), this_thread::get_id() != _main_thread_id ? fun_name+"-": std::string());
        }
        return true;
    }
    return false;
}
bool ExecuterBridge::execute_help(const func_enum& fun_code, const std::string& function_name) {
    auto it = functions_bridge_help_description.find(fun_code);
    auto it_short = functions_bridge_help_short_description.find(fun_code);
    if(it == functions_bridge_help_description.end() && it_short == functions_bridge_help_short_description.end()){
        return false;
    }
    std::ostringstream ss;
    if(it_short == functions_bridge_help_short_description.end()) {
        ss << ConsoleStatusColor::warning << function_name << " - Short description not found" << endl;
    } else {
        ss << ConsoleStatusColor::info << (*it_short).second << endl;
    }
    if(it == functions_bridge_help_description.end()) {
        ss << ConsoleStatusColor::warning << function_name << " - Extended description not found" << endl;
    } else {
        ss << ConsoleStatusColor::help << (*it).second << endl;
    }
    _console_writer->print_result(Status::Success, chrono::system_clock::now() - _timer_start, ss.str());
    return true;
}

std::string ExecuterBridge::get_all_function_help_printable_string() {
    std::ostringstream ss;
    vector<std::string> tmp;
    tmp.clear();
    for(auto &item : functions_bridge){
        tmp.push_back(item.first);
    }
    sort(tmp.begin(), tmp.end());
    ss << ConsoleStatusColor::help << "All Api Functions: " << endl;
    for(auto &item : tmp){
        ss << ConsoleStatusColor::ok << item << ConsoleStatusColor::normal << " - " << ConsoleStatusColor::info << functions_bridge_help_short_description.at(functions_bridge.at(item)) << endl;
    }
    return ss.str();
}

Poco::Dynamic::Var ExecuterBridge::getS_var(const string &key){
    auto it = session.find(key);
    if(it == session.end()){
        return Poco::Dynamic::Var(key);
    }
    return Poco::Dynamic::Var(*((*it).second));
}

void ExecuterBridge::set_api_creds(const std::string &api_key_id, const std::string &api_key_secret, const std::string &url) {
    _api_key_id = api_key_id;
    _api_key_secret = api_key_secret;
    _url = url;
}