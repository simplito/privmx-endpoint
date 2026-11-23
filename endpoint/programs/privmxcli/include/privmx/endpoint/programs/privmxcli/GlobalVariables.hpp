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
#include <iostream>
#include <mutex>
#include <string>
#include <Poco/Dynamic/Var.h>
#include <Poco/JSON/Array.h>
#include <Poco/JSON/Object.h>
#include <Poco/JSON/Parser.h>
#include <Poco/Path.h>
#include <Poco/StringTokenizer.h>
#include <readline/readline.h>
#include <readline/history.h>

#include "privmx/utils/Utils.hpp"

#include "privmx/endpoint/programs/privmxcli/vars/function_enum.hpp"
#include "privmx/endpoint/programs/privmxcli/vars/function_names_map.hpp"

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
    bool quiet = false;
    get_format_type get_format = get_format_type::default_std;
};

using TokensInfo = std::vector<std::tuple<std::string, token_type>>;

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
inline const std::string last_result_var = "last_result";
inline bool config_auto_completion = false;
inline std::string use_path = "";
inline std::string history_file_path = Poco::Path(Poco::Path::cacheHome(), "privmxcli_history").toString();

// keeps the real stdout even when quiet mode points std::cout at stderr
inline std::ostream result_output(std::cout.rdbuf());

// ponytail: only the helpers below lock; direct iteration over session (completion, getAllVars) still races with the event thread
inline std::mutex session_mutex;

inline std::string varToSessionString(const Poco::Dynamic::Var &value) {
    if(value.isEmpty()) {
        return "null";
    }
    if(value.type() == typeid(Poco::JSON::Object::Ptr) || value.type() == typeid(Poco::JSON::Array::Ptr)) {
        return privmx::utils::Utils::stringifyVar(value);
    }
    return value.convert<std::string>();
}

inline void setSessionVar(const std::string &key, const Poco::Dynamic::Var &value) {
    std::lock_guard<std::mutex> lock(session_mutex);
    auto it = session.find(key);
    if(it == session.end()) {
        session[key] = std::make_shared<Poco::Dynamic::Var>(value);
        return;
    }
    it->second->operator=(value);
}

// a command result is always readable as last_result, an assignment stores it under its own name too
inline void setResultVar(const std::string &key, const Poco::Dynamic::Var &value) {
    setSessionVar(key, value);
    if(key != last_result_var) {
        setSessionVar(last_result_var, value);
    }
}

// a dotted key walks into the JSON held by its first segment, e.g. ${last_result.solutionId} or ${last_result.readItems.0.contextId}
inline Poco::Dynamic::Var getSessionVar(const std::string &key) {
    std::lock_guard<std::mutex> lock(session_mutex);
    auto it = session.find(key);
    if(it != session.end()) {
        return Poco::Dynamic::Var(*(it->second));
    }
    auto dot = key.find('.');
    if(dot == std::string::npos) {
        return Poco::Dynamic::Var(key);
    }
    auto base = session.find(key.substr(0, dot));
    if(base == session.end() || !base->second->isString()) {
        return Poco::Dynamic::Var(key);
    }
    Poco::Dynamic::Var node;
    try {
        node = Poco::JSON::Parser().parse(base->second->convert<std::string>());
    } catch (...) {
        return Poco::Dynamic::Var(key);
    }
    Poco::StringTokenizer path(key.substr(dot + 1), ".");
    for(const auto &segment : path) {
        if(node.type() == typeid(Poco::JSON::Object::Ptr)) {
            auto object = node.extract<Poco::JSON::Object::Ptr>();
            if(!object->has(segment)) {
                return Poco::Dynamic::Var(key);
            }
            node = object->get(segment);
        } else if(node.type() == typeid(Poco::JSON::Array::Ptr)) {
            auto array = node.extract<Poco::JSON::Array::Ptr>();
            std::size_t index = 0;
            try {
                index = std::stoul(segment);
            } catch (...) {
                return Poco::Dynamic::Var(key);
            }
            if(index >= array->size()) {
                return Poco::Dynamic::Var(key);
            }
            node = array->get(index);
        } else {
            return Poco::Dynamic::Var(key);
        }
    }
    return Poco::Dynamic::Var(varToSessionString(node));
}

} // privmxcli
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_PRIVMXCLI_UTILS_C_HPP_