/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_PRIVMXCLI_EXECUTER_HPP_
#define _PRIVMXLIB_ENDPOINT_PRIVMXCLI_EXECUTER_HPP_

#include <chrono>
#include <thread>
#include <readline/readline.h>

#include "privmx/endpoint/programs/privmxcli/GlobalVariables.hpp"
#include "privmx/endpoint/programs/privmxcli/LoadingAnimation.hpp"
#include "privmx/endpoint/programs/privmxcli/ConsoleWriter.hpp"
#include "privmx/endpoint/programs/privmxcli/ExecuterEndpoint.hpp"
#include "privmx/endpoint/programs/privmxcli/ExecuterBridge.hpp"
#include "privmx/endpoint/programs/privmxcli/vars/function_enum.hpp"

namespace privmx {
namespace endpoint {
namespace privmxcli {

class Executer {
public:
    Executer(std::thread::id main_thread_id, std::shared_ptr<CliConfig> config, std::shared_ptr<ConsoleWriter> console_writer);
    void execute(const Tokens &st);
    func_enum getFunc(std::string func_name);
    std::shared_ptr<Poco::Dynamic::Var> getS_ptr(const std::string &key);
    Poco::Dynamic::Var getS_var(const std::string &key);
private:
    void exec_help(const Tokens &st);
    void exec_help();
    void exec_help(func_enum fun_code, const std::string& fun_name);
    void setFA(const std::string &key, const std::string &value);
    void setS(const std::string &key, const Poco::Dynamic::Var &value);
    void setSA(const std::string &key, const std::string &value);
    void copyS(const std::string &key, const std::string &value);
    void addF(const std::string &key, const Poco::Dynamic::Var &value);
    void addB(const std::string &key, const Poco::Dynamic::Var &value);
    std::string getS_printable(const std::string &key);
    std::string evalS(const std::string &value_string);
    std::string readFileToString(const std::string& path);
    void writeFileFromString(const std::string& content, const std::string& path);
    std::vector<std::string> getAllVars();
    unsigned int sleep_for(const int& T);
    unsigned int sleep_for_random(const int& T1, const int& T2);
    bool isValidVarName(const std::string &key);
    bool isNumber(const std::string &val);

    std::thread::id _main_thread_id;
    std::shared_ptr<CliConfig> _config;
    std::shared_ptr<ConsoleWriter> _console_writer;
    ExecuterEndpoint _endpoint;
    ExecuterBridge _bridge;

    std::chrono::_V2::system_clock::time_point _timer_start = std::chrono::system_clock::now();

    const std::unordered_map<func_enum, std::string> functions_internal_help_description = {
        {quit, "quit"},
        {falias, 
            "falias NEW_ALIAS FUNCTION_NAME\n"
            "\tFunction  alias"
        },
        {salias, 
            "alias NEW_ALIAS, VAR_NAME\n"
            "\tVar alias"
        },
        {scopy, 
            "copy NEW_VAR, VAR_NAME\n"
            "\tVar copy"
        },
        {sset, 
            "set VAR_NAME, VAR_VALUE\n"
            "\tSet new var"
        },
        // {ssetArray, "setArray ARRAY_NAME VAR_VALUE ..."},
        {sget, 
            "get VAR_NAME"
        },
        {sreadFile, 
            "setFromFile VAR_NAME path"
        },
        {swriteFile, 
            "saveToFile VAR_NAME path"
        },
        {help, 
            "help FUNCTION_NAME\n"
            "\talso you can use ? afer function name to get help"
        },
        {loopStart, 
            "loopStart N OPTIONAL<ID>\n"
            "\tloops everything N times to loopStop\n"
            "\tId is optional"
        },
        {loopStop, 
            "loopStop"
        },
        {a_sleep, 
            "sleep T\n"
            "\tsleep for T ms\n"
            "sleep(T1,T2)\n"
            "\tsleep for random time between T1 T2ms"
        },
        {addFront, 
            "addFront VAR_NAME_1 VAR_NAME_2)\n"
            "\tadd second var on the front of the first var"
        },
        {addBack, 
            "addBack VAR_NAME_1 VAR_NAME_2\n"
            "\tadd second var on the back of the first var"
        },
        {addFrontString, 
            "addFront VAR_NAME, DATA_STRING)\n"
            "\tadd DATA_STRING on the front of var"
        },
        {addBackString, 
            "addBack VAR_NAME, DATA_STRING)\n"
            "\tadd DATA_STRING on the back of var"
        },
        {use, 
            "addBack PATH)\n"
            "\tsets path"
        }
    };
    const std::unordered_map<func_enum, std::string> functions_internal_help_short_description = {
        {quit, "quit"},
        {falias, "create function alias"},
        {salias, "create var alias"},
        {scopy, "copy var"},
        {sset, "Set new var"},
        // {ssetArray, "setArray ARRAY_NAME VAR_VALUE ..."},
        {sget, "gets var"},
        {sreadFile, "reads from file"},
        {swriteFile, "write to file"},
        {help, "help"},
        {loopStart, "marker to start loop"},
        {loopStop, "marker to stop loop"},
        {a_sleep, "sleep for"},
        {addFront, "add var on the front of the other"},
        {addBack, "add var on the back of the other"},
        {addFrontString, "add string on the front of var"},
        {addBackString, "add string on the front of var"},
        {use, "set default path"}
    };
};

} // privmxcli
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_PRIVMXCLI_EXECUTER_HPP_