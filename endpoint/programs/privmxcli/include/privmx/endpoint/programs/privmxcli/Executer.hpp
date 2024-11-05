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

#include <algorithm>
#include <chrono>
#include <iostream>
#include <fstream>
#include <thread>
#include <unordered_map>

#include <readline/readline.h>

#include <Poco/Environment.h>
#include <Poco/Dynamic/Var.h>
#include <Poco/JSON/Array.h>
#include <Poco/JSON/Object.h>
#include <Poco/StringTokenizer.h>
#include <Poco/String.h>

#include <Pson/BinaryString.hpp>
#include "privmx/crypto/Crypto.hpp"
#include "privmx/utils/Utils.hpp"
#include "privmx/utils/PrivmxException.hpp"
#include "privmx/endpoint/core/Exception.hpp"

#include "privmx/endpoint/programs/privmxcli/GlobalVariables.hpp"
#include "privmx/endpoint/programs/privmxcli/LoadingAnimation.hpp"


#define ARG1(x) getS(st[1])x
#define ARG2(x) getS(st[2])x

#define ARG_INT .convert<int>()
#define ARG_STR .convert<string>().data()
#define ARG_ARR .extract<StringArray>().data()

#define CHECK_ST_ARGS(n) if(st.size() != (n + 1)) {                                                     \
    ERROR_CLI_INVALID_ARG_COUNT()                                                                     \
}                                                                                                       \

#define CHECK_ST_ARGS_2(n1, n2) if(st.size() < (n1 + 1) || st.size() > (n2 + 1)) {                      \
    ERROR_CLI_INVALID_ARG_COUNT()                                                                     \
}

#define ERROR_CLI_INVALID_ARG_COUNT() ERROR_CLI("Invalid args count")

#define ERROR_CLI(ERROR_TEXT)                                                                           \
executePrePrintOutput(true);                                                                            \
std::cerr << ConsoleStatusColor::error << ERROR_TEXT << std::endl;                                      \
executePostPrint();                                                                                     \
return;                                                                                                 \

#define ARGS0()
#define ARGS1(arg1) ARG1(arg1),
#define ARGS2(arg1, arg2) ARG1(arg1), ARG2(arg2),



namespace privmx {
namespace endpoint {
namespace privmxcli {

class Executer {
public:
    Executer(std::thread::id main_thread_id, CliConfig config);
    void updateCliConfig(CliConfig config);
    void execute(const Tokens &st);
    func_enum getFunc(std::string func_name);
    std::shared_ptr<Poco::Dynamic::Var> getS_ptr(const std::string &key);
    Poco::Dynamic::Var getS_var(const std::string &key);
private:
    void exec_help(const Tokens &st);
    void setFA(const std::string &key, const std::string &value);
    void setS(const std::string &key, const Poco::Dynamic::Var &value);
    void setSA(const std::string &key, const std::string &value);
    void copyS(const std::string &key, const std::string &value);
    void addF(const std::string &key, const Poco::Dynamic::Var &value);
    void addB(const std::string &key, const Poco::Dynamic::Var &value);
    void getS_print_value(const std::string &key);
    std::string evalS(const std::string &value_string);
    size_t findNext$Pos(const std::string &value_string, size_t skip = 0);
    std::string readFileToString(const std::string& path);
    void writeFileFromString(const std::string& content, const std::string& path);
    void executeApiFunction(const func_enum& fun_code, const std::string& fun_name, const std::string& st);

    void executePrePrintInfo(const std::string& info_name = "");
    void executePrePrintOutput(bool is_error = false, const std::string& extra_info = "");
    void executePrePrintOutputStatus(bool is_error = false, const std::string& extra_info = "");
    void executePrePrintOutputResult(bool is_error = false, const std::string& extra_info = "");
    void executePostPrint();
    void printAllFunctions();
    void printAllVars();
    void printTimestamp(std::chrono::_V2::system_clock::time_point start, std::chrono::_V2::system_clock::time_point stop = std::chrono::system_clock::now());
    unsigned int sleep_for(const int& T);
    unsigned int sleep_for_random(const int& T1, const int& T2);
    bool isValidVarName(const std::string &key);
    bool isNumber(const std::string &val);

    std::thread::id _main_thread_id;
    CliConfig _config;
    LoadingAnimation _loading_animation;
    std::shared_ptr<ApiVar> _endpoint;
    

    std::chrono::_V2::system_clock::time_point _timer_start = std::chrono::system_clock::now();
    std::chrono::_V2::system_clock::time_point _timer_stop = std::chrono::system_clock::now();
};

} // privmxcli
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_PRIVMXCLI_EXECUTER_HPP_