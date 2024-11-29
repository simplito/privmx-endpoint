/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_PRIVMXCLI_DATA_PROCESOR_HPP_
#define _PRIVMXLIB_ENDPOINT_PRIVMXCLI_DATA_PROCESOR_HPP_

#include <algorithm>
#include <unordered_map>
#include <tuple>

#include <Poco/String.h>

#include "privmx/endpoint/programs/privmxcli/Executer.hpp"
#include "privmx/endpoint/programs/privmxcli/Tokenizer.hpp"


namespace privmx {
namespace endpoint {
namespace privmxcli {

struct Loop {
    std::vector<Tokens> commands;
    int number_of_times;
    std::string id;
    std::chrono::_V2::system_clock::time_point start;
    std::vector<std::chrono::duration<double>> diffs;
};


class DataProcesor {
public:
    DataProcesor(std::shared_ptr<Executer> executer, std::thread::id main_thread_id, std::shared_ptr<CliConfig> config);

    int processLine(const std::string &input_line); 
    // jeżeli 1 to brakuje danych by mieć komendę
    // jeżeli 0 to wszystko ok;
    // jeżeli -1 to wszystko nie poprawny JSON;
    void clean();
    
private:
    Tokens ParseCommand(std::string command);
    void ExecuteCommand(const Tokens& command);
    std::chrono::duration<double> getTimestamp(std::chrono::_V2::system_clock::time_point start);
    std::string evalArg(std::string value);
    std::tuple<size_t, size_t> findNextVariablePos(const std::string &data, size_t skip = 0);
    size_t findNextDolarPos(const std::string &data, size_t skip = 0);
    void print_msg(const std::string &message, const std::string &data = "", bool is_error = false);
    std::optional<std::string> procesRawToken(const token_type& type, const std::string& val);

    std::shared_ptr<Executer> _executer;
    std::string _working_command;
    std::shared_ptr<CliConfig> _config;
    int _working_command_braces;
    int _working_command_square_brackets;
    bool _working_command_reading_string;
    char _working_command_string_char;
    std::vector<Loop> _loops;
    int _loops_id_gen = 0;
};

} // privmxcli
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_PRIVMXCLI_DATA_PROCESOR_HPP_