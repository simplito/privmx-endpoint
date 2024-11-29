/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/
#include "privmx/endpoint/programs/privmxcli/ConsoleWriter.hpp"
#include "privmx/endpoint/programs/privmxcli/colors/Colors.hpp"
#include <privmx/utils/Debug.hpp>

using namespace privmx::endpoint::privmxcli;

ConsoleWriter::ConsoleWriter(std::thread::id main_thread_id, std::shared_ptr<CliConfig>  config) : 
    _main_thread_id(main_thread_id), _config(config), _loading_animation(LoadingAnimation()) {}

void ConsoleWriter::print_info(std::string message, bool disable_animation) {
    if(_config->is_rl_input && std::this_thread::get_id() != _main_thread_id){
        rl_clear_visible_line();
    }
    std::cout << ConsoleStatusColor::normal << "-> " << colors::ConsoleColor::blue << message << colors::ConsoleColor::reset;
    if (std::this_thread::get_id() == _main_thread_id) {
        std::cout << " ... ";
        #ifdef PRIVMX_USE_DEBUG
        std::cout << std::endl;
        #endif //PRIVMX_USE_DEBUG
    } else {
        std::cout << std::endl;
    }
    if (_config->is_rl_input && std::this_thread::get_id() == _main_thread_id) {
        #ifndef PRIVMX_USE_DEBUG
        _loading_animation.start();
        #endif //PRIVMX_USE_DEBUG
    }
}

void ConsoleWriter::print_result(Status status, std::chrono::duration<double> time, const std::string& result_message, const std::string& status_info) {
    if(_config->is_rl_input && std::this_thread::get_id() == _main_thread_id){
        #ifndef PRIVMX_USE_DEBUG
        _loading_animation.stop();
        #endif //PRIVMX_USE_DEBUG
    }
    if(std::this_thread::get_id() == _main_thread_id) {
        if(status == Status::Error || status == Status::ErrorInvalidInput) {
            std::cout << ConsoleStatusColor::error << "ERR" << ConsoleStatusColor::normal << " ";
        } else if(status == Status::Success) {
            std::cout  << ConsoleStatusColor::ok << "OK" << ConsoleStatusColor::normal << " ";
        }
        if(_config->add_timestamps && std::this_thread::get_id() == _main_thread_id) {
            std::cout << ConsoleStatusColor::info << std::to_string(time.count()*1000) << "ms";
        }
    }
    std::cout << std::endl;
    if(status == Status::Error || status == Status::ErrorInvalidInput) {
        std::cout << ConsoleStatusColor::normal << "-> " << ConsoleStatusColor::error << status_info << "RESULT" << ConsoleStatusColor::normal << ":" << std::endl;
        if(!result_message.empty()) {
            std::cout << ConsoleStatusColor::error << result_message << colors::ConsoleColor::reset << std::endl;
        }
    } else if(status == Status::Success) {
        std::cout << ConsoleStatusColor::normal << "-> " << ConsoleStatusColor::ok << status_info << "RESULT" << ConsoleStatusColor::normal << ":" << std::endl;
        if(!result_message.empty()) {
            std::cout << ConsoleStatusColor::normal << result_message << colors::ConsoleColor::reset << std::endl;
        }
    }
    if(_config->is_rl_input && std::this_thread::get_id() != _main_thread_id){
        rl_on_new_line();
        rl_redisplay();
    }
    if(status == Status::Error && _config->stop_on_error) exit(EXIT_FAILURE);
}