/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/
#include <string>
#include <thread>
#include <chrono>
#include <readline/readline.h>
#include "privmx/endpoint/programs/privmxcli/LoadingAnimation.hpp"
#include "privmx/endpoint/programs/privmxcli/GlobalVariables.hpp"

#ifndef _PRIVMXLIB_ENDPOINT_PRIVMXCLI_CONSOLE_WRITER_HPP_
#define _PRIVMXLIB_ENDPOINT_PRIVMXCLI_CONSOLE_WRITER_HPP_

namespace privmx {
namespace endpoint {
namespace privmxcli {

enum Status {
    Success,
    ErrorInvalidInput,
    Error,
};

class ConsoleWriter {
public:
    ConsoleWriter(std::thread::id main_thread_id, std::shared_ptr<CliConfig>  config);
    void print_info(std::string message, bool disable_animation = false);
    void print_result(Status status, std::chrono::duration<double> time, std::string result_message = std::string(), std::string status_info = std::string());
private:
    std::thread::id _main_thread_id;
    std::shared_ptr<CliConfig> _config;
    LoadingAnimation _loading_animation;
};


} // privmxcli
} // endpoint
} // privmx


#endif // _PRIVMXLIB_ENDPOINT_PRIVMXCLI_EXECUTER_HPP_