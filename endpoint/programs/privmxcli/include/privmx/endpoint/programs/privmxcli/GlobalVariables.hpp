/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_PRIVMXCLI_UTILS_C_HPP_
#define _PRIVMXLIB_ENDPOINT_PRIVMXCLI_UTILS_C_HPP_

#include <unordered_map>
#include <tuple>
#include <cstdlib>
#include <string>
#include <Poco/Dynamic/Var.h>
#include <Poco/Path.h>
#include <readline/readline.h>
#include <readline/history.h>

#include "privmx/endpoint/programs/privmxcli/vars/function_enum.hpp"
#include "privmx/endpoint/programs/privmxcli/vars/function_names_map.hpp"
#include "privmx/endpoint/programs/privmxcli/vars/function_descriptions_map.hpp"
#include "privmx/endpoint/programs/privmxcli/vars/function_execute_map.hpp"

namespace privmx {
namespace endpoint {
namespace privmxcli {

using Tokens = std::vector<std::string>;
enum token_type {
    text,
    text_no_eval,
    text_string,
    text_string_no_eval,
    number,
    JSON
};
enum get_format_type {
    default_std,
    bash,
    cpp,
    python
};

struct CliConfig {
    bool std_input = false;
    bool update_history = false;
    bool add_timestamps = false;
    bool stop_on_error = false;
    bool is_rl_input = false;
    get_format_type get_format = get_format_type::default_std;
};

using TokensInfo = std::vector<std::tuple<std::string, token_type>>;

inline std::unordered_map<std::string, func_enum> functions_internal = {
    {"quit", quit},
    {"exit", quit},
    {"falias", falias},
    {"alias", salias},
    {"copy", scopy},
    {"set", sset},
    // {"setArray", ssetArray},
    {"get", sget},
    {"setFromFile", sreadFile},
    {"saveToFile", swriteFile},
    {"help", help},
    {"loopStart", loopStart},
    {"loopStop", loopStop},
    {"sleep", a_sleep},
    {"addFront", addFront},
    {"addBack", addBack},
    {"addFrontString", addFrontString},
    {"addBackString", addBackString},
    {"use", use}
};

inline std::unordered_map<std::string, std::string> func_aliases = {
    {"c", "copy"},
    {"fa", "falias"},
    {"a", "alias"},
    // {"sA", "setArray"},
    {"g", "get"},
    {"s", "set"},
    {"h", "help"},
    {"aF", "addFront"},
    {"aB", "addBack"},
    {"aFS", "addFrontString"},
    {"aBS", "addBackString"}
};

inline std::unordered_map<std::string, std::shared_ptr<Poco::Dynamic::Var>> session = {};
inline bool config_auto_completion = false;
inline std::string use_path = "";
inline std::string history_file_path = Poco::Path(Poco::Path::cacheHome(), "privmxcli_history").toString();

} // privmxcli
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_PRIVMXCLI_UTILS_C_HPP_