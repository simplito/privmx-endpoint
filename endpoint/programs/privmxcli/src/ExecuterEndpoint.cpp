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

#include "privmx/endpoint/programs/privmxcli/ExecuterEndpoint.hpp"
#include "privmx/endpoint/programs/privmxcli/colors/Colors.hpp"

#include "privmx/utils/PrivmxException.hpp"
#include "privmx/endpoint/core/VarSerializer.hpp"
#include "privmx/endpoint/thread/ThreadVarSerializer.hpp"
#include "privmx/endpoint/store/StoreVarSerializer.hpp"
#include "privmx/endpoint/inbox/InboxVarSerializer.hpp"

using namespace std;
using namespace privmx::endpoint::privmxcli;

ExecuterEndpoint::ExecuterEndpoint(std::thread::id main_thread_id, std::shared_ptr<CliConfig> config, std::shared_ptr<ConsoleWriter> console_writer) : 
    _main_thread_id(main_thread_id), _config(config), _console_writer(console_writer) 
{
    core::VarSerializer serializer = core::VarSerializer(core::VarSerializer::Options{.addType = true, .binaryFormat = core::VarSerializer::Options::STD_STRING});
    std::shared_ptr<core::EventQueueVarInterface> event = std::make_shared<core::EventQueueVarInterface>(core::EventQueue::getInstance(), serializer);
    std::shared_ptr<core::ConnectionVarInterface> connection = std::make_shared<core::ConnectionVarInterface>(serializer);
    std::shared_ptr<core::BackendRequesterVarInterface> backendRequester = std::make_shared<core::BackendRequesterVarInterface>(serializer);
    std::shared_ptr<crypto::CryptoApiVarInterface> crypto = std::make_shared<crypto::CryptoApiVarInterface>(serializer);
    std::shared_ptr<thread::ThreadApiVarInterface> thread = std::make_shared<thread::ThreadApiVarInterface>(connection->getApi(),serializer);
    std::shared_ptr<store::StoreApiVarInterface> store = std::make_shared<store::StoreApiVarInterface>(connection->getApi(),serializer);
    std::shared_ptr<inbox::InboxApiVarInterface> inbox = std::make_shared<inbox::InboxApiVarInterface>(connection->getApi(),thread->getApi(), store->getApi(),serializer);
    _endpoint = std::make_shared<ApiVar>(serializer, event, connection, backendRequester, crypto, thread, store, inbox);
    
}
bool ExecuterEndpoint::execute(const func_enum& fun_code, const Tokens &st) {
    std::chrono::duration<double> time = chrono::system_clock::now() - _timer_start;
    const std::string fun_name = st[0];
    auto it = functions_endpoint_execute.find(fun_code);
    if(it != functions_endpoint_execute.end()) {
        auto it_2 = functions_endpoint_action_description.find(fun_code);
        if(it_2 == functions_endpoint_action_description.end()){
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
        std::function<Poco::Dynamic::Var (std::shared_ptr<ApiVar>, const Poco::JSON::Array::Ptr &)> exec = (*it).second;
        Poco::JSON::Object::Ptr result = Poco::JSON::Object::Ptr(new Poco::JSON::Object());
        _timer_start = std::chrono::system_clock::now();
        try {
            if(st.size() != (1 + 1)) {
                _console_writer->print_result(Status::ErrorInvalidInput, chrono::system_clock::now() - _timer_start, "Invalid args count" );
                return true; 
            }
            auto raw_JSON_arg = st[1];
            auto evaluated_JSON_arg_var = getS_var(raw_JSON_arg);
            auto evaluated_JSON_arg_string = evaluated_JSON_arg_var.convert<std::string>();
            Poco::JSON::Array::Ptr args = privmx::utils::Utils::parseJson(evaluated_JSON_arg_string).extract<Poco::JSON::Array::Ptr>();
            Poco::Dynamic::Var value;
            value = exec(_endpoint, args);
            std::chrono::duration<double> time = chrono::system_clock::now() - _timer_start;
            std::string output = "null";
            if(!value.isEmpty()) {
                output = privmx::utils::Utils::stringifyVar(value, true);
            }
            _console_writer->print_result(Status::Success, time, output, this_thread::get_id() != _main_thread_id ? fun_name+"-": std::string());
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
bool ExecuterEndpoint::execute_help(const func_enum& fun_code, const std::string& function_name) {
    auto it = functions_endpoint_help_description.find(fun_code);
    auto it_short = functions_endpoint_help_short_description.find(fun_code);
    if(it == functions_endpoint_help_description.end() && it_short == functions_endpoint_help_short_description.end()){
        return false;
    }
    std::ostringstream ss;
    if(it_short == functions_endpoint_help_short_description.end()) {
        ss << ConsoleStatusColor::warning << function_name << " - Short description not found" << endl;
    } else {
        ss << ConsoleStatusColor::info << (*it_short).second << endl;
    }
    if(it == functions_endpoint_help_description.end()) {
        ss << ConsoleStatusColor::warning << function_name << " - Extended description not found" << endl;
    } else {
        ss << ConsoleStatusColor::help << (*it).second << endl;
    }
    _console_writer->print_result(Status::Success, chrono::system_clock::now() - _timer_start, ss.str());
    return true;
}

std::string ExecuterEndpoint::get_all_function_help_printable_string() {
    std::ostringstream ss;
    vector<std::string> tmp;
    tmp.clear();
    for(auto &item : functions_endpoint){
        tmp.push_back(item.first);
    }
    sort(tmp.begin(), tmp.end());
    ss << ConsoleStatusColor::help << "All Api Functions: " << endl;
    for(auto &item : tmp){
        ss << ConsoleStatusColor::ok << item << ConsoleStatusColor::normal << " - " << ConsoleStatusColor::info << functions_endpoint_help_short_description.at(functions_endpoint.at(item)) << endl;
    }
    return ss.str();
}

Poco::Dynamic::Var ExecuterEndpoint::getS_var(const string &key){
    auto it = session.find(key);
    if(it == session.end()){
        return Poco::Dynamic::Var(key);
    }
    return Poco::Dynamic::Var(*((*it).second));
}